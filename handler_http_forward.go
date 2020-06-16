package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"text/template"
	"time"

	"github.com/phuslu/log"
	"github.com/tidwall/shardmap"
	"github.com/valyala/fastjson"
	"golang.org/x/net/publicsuffix"
)

type HTTPForwardHandler struct {
	Next           http.Handler
	Config         HTTPConfig
	ForwardLogger  log.Logger
	RegionResolver *RegionResolver
	LocalDialer    *LocalDialer
	Transport      *http.Transport
	Upstreams      map[string]*http.Transport
	Functions      template.FuncMap

	ServerNames      StringSet
	AllowDomains     StringSet
	DenyDomains      StringSet
	PolicyTemplate   *template.Template
	AuthTemplate     *template.Template
	UpstreamTemplate *template.Template
	AuthCache        *shardmap.Map
}

func (h *HTTPForwardHandler) Load() error {
	var err error

	h.ServerNames = NewStringSet(h.Config.ServerName)

	expandDomains := func(domains []string) (a []string) {
		for _, s := range domains {
			switch {
			case strings.HasPrefix(s, "@"):
				data, err := ioutil.ReadFile(s[1:])
				if err != nil {
					log.Error().Err(err).Str("forward_domain_file", s[1:]).Msg("read forward domain error")
					continue
				}
				lines := strings.Split(strings.Replace(string(data), "\r\n", "\n", -1), "\n")
				a = append(a, lines...)
			default:
				a = append(a, s)
			}
		}
		return
	}

	h.AllowDomains = NewStringSet(expandDomains(h.Config.ForwardAllowDomains))
	h.DenyDomains = NewStringSet(expandDomains(h.Config.ForwardDenyDomains))

	if s := h.Config.ForwardPolicy; s != "" {
		if h.PolicyTemplate, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	if s := h.Config.ForwardAuth; s != "" {
		if h.AuthTemplate, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	if s := h.Config.ForwardUpstream; s != "" {
		if h.UpstreamTemplate, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	if h.Config.ForwardOutboundIp != "" {
		if runtime.GOOS != "linux" {
			log.Fatal().Strs("server_name", h.Config.ServerName).Msg("option outbound_ip is only available on linux")
		}
		if h.Config.ForwardUpstream != "" {
			log.Fatal().Strs("server_name", h.Config.ServerName).Msg("option outbound_ip is confilict with option upstream")
		}

		var dialer = *h.LocalDialer
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(h.Config.ForwardOutboundIp)}
		dialer.Control = (DailerController{BindAddressNoPort: true}).Control

		h.Transport = &http.Transport{
			DialContext:         dialer.DialContext,
			TLSClientConfig:     h.Transport.TLSClientConfig,
			TLSHandshakeTimeout: h.Transport.TLSHandshakeTimeout,
			IdleConnTimeout:     h.Transport.IdleConnTimeout,
			MaxIdleConns:        h.Transport.MaxIdleConns,
			DisableCompression:  h.Transport.DisableCompression,
		}
	}

	h.AuthCache = shardmap.New(0)

	return nil
}

func (h *HTTPForwardHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(RequestInfo)

	var err error
	var host = req.Host
	if h, _, err := net.SplitHostPort(req.Host); err == nil {
		host = h
	}

	// if h.ServerNames.Contains(host) || net.ParseIP(ri.RemoteIP).IsLoopback() {
	if h.ServerNames.Contains(host) && req.Method != http.MethodConnect {
		log.Debug().Str("server_name", ri.ServerName).Str("remote_ip", ri.RemoteIP).Interface("forward_server_names", h.ServerNames).Str("request_host", req.Host).Msg("fallback to next handler")
		h.Next.ServeHTTP(rw, req)
		return
	}

	var domain = host
	if net.ParseIP(domain) == nil {
		if s, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
			domain = s
		}
	}

	if h.Config.ForwardPolicy == "" {
		h.Next.ServeHTTP(rw, req)
		return
	}

	var bypassAuth bool

	var sb strings.Builder
	if h.PolicyTemplate != nil {
		sb.Reset()
		err = h.PolicyTemplate.Execute(&sb, struct {
			Request         *http.Request
			ClientHelloInfo *tls.ClientHelloInfo
		}{req, ri.ClientHelloInfo})
		if err != nil {
			log.Error().Err(err).Str("server_name", ri.ServerName).Str("remote_ip", ri.RemoteIP).Str("forward_policy", h.Config.ForwardPolicy).Interface("client_hello_info", ri.ClientHelloInfo).Interface("tls_connection_state", req.TLS).Msg("execute forward_policy error")
			h.Next.ServeHTTP(rw, req)
			return
		}

		output := strings.TrimSpace(sb.String())
		log.Debug().Str("server_name", ri.ServerName).Str("remote_ip", ri.RemoteIP).Interface("client_hello_info", ri.ClientHelloInfo).Interface("tls_connection_state", req.TLS).Str("forward_policy_output", output).Msg("execute forward_policy ok")

		switch output {
		case "", "proxy_pass":
			h.Next.ServeHTTP(rw, req)
			return
		case "reject", "deny":
			RejectRequest(rw, req)
			return
		case "reset", "close":
			if hijacker, ok := rw.(http.Hijacker); ok {
				if conn, _, err := hijacker.Hijack(); err == nil {
					conn.Close()
				}
			}
			return
		case "require_auth", "require_proxy_auth", "require_www_auth":
			var authCode int
			var authHeader, authText string
			switch output {
			case "require_www_auth":
				authCode = http.StatusUnauthorized
				authHeader = "www-authenticate"
				authText = "Authentication Required"
			default:
				authCode = http.StatusProxyAuthRequired
				authHeader = "proxy-authenticate"
				authText = "Authentication Required"
			}
			resp := &http.Response{
				StatusCode: authCode,
				Header: http.Header{
					"content-type": []string{"text/plain; charset=UTF-8"},
					authHeader:     []string{fmt.Sprintf("Basic realm=\"%s\"", authText)},
				},
				Request:       req,
				ContentLength: int64(len(authText)),
				Body:          ioutil.NopCloser(strings.NewReader(authText)),
			}
			for key, values := range resp.Header {
				for _, value := range values {
					rw.Header().Add(key, value)
				}
			}
			rw.WriteHeader(resp.StatusCode)
			io.Copy(rw, resp.Body)
			return
		case "bypass_auth":
			bypassAuth = true
		}
	}

	var ui ForwardUserInfo
	if h.AuthTemplate != nil && !bypassAuth {
		ui, err = h.GetAuthInfo(ri, req)
		if err != nil {
			log.Warn().Err(err).Str("server_name", ri.ServerName).Str("server_addr", ri.ServerAddr).Str("username", ui.Username).Str("proxy_authorization", req.Header.Get("proxy-authorization")).Str("remote_ip", ri.RemoteIP).Str("http_method", req.Method).Str("http_proto", req.Proto).Msg("auth error")
			RejectRequest(rw, req)
			return
		}
	}

	if !ui.VIP {
		if !h.AllowDomains.Empty() || !h.DenyDomains.Empty() {
			if !h.AllowDomains.Empty() && !h.AllowDomains.Contains(domain) {
				RejectRequest(rw, req)
				return
			}
			if h.DenyDomains.Contains(domain) {
				RejectRequest(rw, req)
				return
			}
		}
		if ui.SpeedLimit == 0 && h.Config.ForwardSpeedLimit > 0 {
			ui.SpeedLimit = h.Config.ForwardSpeedLimit
		}
	}

	transport := h.Transport
	if h.UpstreamTemplate != nil {
		sb.Reset()
		err := h.UpstreamTemplate.Execute(&sb, struct {
			Request         *http.Request
			ClientHelloInfo *tls.ClientHelloInfo
			User            ForwardUserInfo
		}{req, ri.ClientHelloInfo, ui})
		if err != nil {
			log.Error().Err(err).Str("forward_upstream", h.Config.ForwardUpstream).Msg("execute forward_upstream error")
			h.Next.ServeHTTP(rw, req)
			return
		}

		if s := strings.TrimSpace(sb.String()); s != "" {
			tr, ok := h.Upstreams[s]
			if !ok {
				log.Error().Str("upstream", s).Msg("no upstream exists")
				h.Next.ServeHTTP(rw, req)
				return
			}
			transport = tr
		}
	}

	log.Info().Str("server_name", ri.ServerName).Str("server_addr", ri.ServerAddr).Str("tls_version", ri.TLSVersion.String()).Str("username", ui.Username).Str("remote_ip", ri.RemoteIP).Str("http_method", req.Method).Str("http_host", host).Str("http_domain", domain).Str("http_url", req.URL.String()).Str("http_proto", req.Proto).Str("user_agent", req.UserAgent()).Msg("forward request")

	var transmitBytes int64
	switch req.Method {
	case http.MethodConnect:
		if req.URL.Host == ri.ServerName {
			// FIXME: handle self-connect clients
		}

		conn, err := transport.DialContext(req.Context(), "tcp", req.URL.Host)
		if err != nil {
			log.Error().Err(err).Str("host", req.URL.Host).Msg("dial host error")
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}

		var w io.Writer
		var r io.Reader

		if req.ProtoAtLeast(2, 0) {
			flusher, ok := rw.(http.Flusher)
			if !ok {
				http.Error(rw, fmt.Sprintf("%#v is not http.Flusher", rw), http.StatusBadGateway)
				return
			}

			rw.WriteHeader(http.StatusOK)
			flusher.Flush()

			w = FlushWriter{rw}
			r = req.Body
		} else {
			hijacker, ok := rw.(http.Hijacker)
			if !ok {
				http.Error(rw, fmt.Sprintf("%#v is not http.Hijacker", rw), http.StatusBadGateway)
				return
			}
			lconn, _, err := hijacker.Hijack()
			if err != nil {
				http.Error(rw, err.Error(), http.StatusBadGateway)
				return
			}
			defer lconn.Close()

			w = lconn
			r = lconn

			io.WriteString(lconn, "HTTP/1.1 200 OK\r\n\r\n")
		}

		defer conn.Close()

		go io.Copy(conn, r)
		transmitBytes, err = io.Copy(w, NewLimiterReader(conn, ui.SpeedLimit))
		log.Debug().Str("server_name", ri.ServerName).Str("server_addr", ri.ServerAddr).Str("tls_version", ri.TLSVersion.String()).Str("username", ui.Username).Str("remote_ip", ri.RemoteIP).Str("http_method", req.Method).Str("http_host", host).Str("http_domain", domain).Str("http_proto", req.Proto).Str("user_agent", req.UserAgent()).Int64("transmit_bytes", transmitBytes).Err(err).Msg("forward log")
	default:
		if req.Host == "" {
			http.NotFound(rw, req)
			return
		}

		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}

		if req.ContentLength == 0 {
			io.Copy(ioutil.Discard, req.Body)
			req.Body.Close()
			req.Body = nil
		}

		if req.URL.Scheme == "" {
			req.URL.Scheme = "http"
		}

		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}

		h2 := req.ProtoAtLeast(2, 0)
		if h2 {
			req.ProtoMajor = 1
			req.ProtoMinor = 1
			req.Proto = "HTTP/1.1"
		}

		resp, err := transport.RoundTrip(req)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}

		if h2 {
			resp.Header.Del("connection")
			resp.Header.Del("keep-alive")
		}

		for k, vv := range resp.Header {
			for _, v := range vv {
				rw.Header().Add(k, v)
			}
		}

		rw.WriteHeader(resp.StatusCode)
		defer resp.Body.Close()

		transmitBytes, err = io.Copy(rw, NewLimiterReader(resp.Body, ui.SpeedLimit))
		log.Debug().Str("server_name", ri.ServerName).Str("server_addr", ri.ServerAddr).Str("tls_version", ri.TLSVersion.String()).Str("username", ui.Username).Str("remote_ip", ri.RemoteIP).Str("http_method", req.Method).Str("http_host", host).Str("http_domain", domain).Str("http_proto", req.Proto).Str("user_agent", req.UserAgent()).Int64("transmit_bytes", transmitBytes).Err(err).Msg("forward log")
	}

	if h.Config.ForwardLog {
		var country, region, city string
		if h.RegionResolver.MaxmindReader != nil {
			country, region, city, _ = h.RegionResolver.LookupCity(context.Background(), net.ParseIP(ri.RemoteIP))
		} else {
			country, _ = h.RegionResolver.LookupCountry(context.Background(), ri.RemoteIP)
		}
		h.ForwardLogger.Info().Str("server_name", ri.ServerName).Str("server_addr", ri.ServerAddr).Str("tls_version", ri.TLSVersion.String()).Str("username", ui.Username).Str("remote_ip", ri.RemoteIP).Str("remote_country", country).Str("remote_region", region).Str("remote_city", city).Str("http_method", req.Method).Str("http_host", host).Str("http_domain", domain).Str("http_proto", req.Proto).Str("user_agent", req.UserAgent()).Int64("transmit_bytes", transmitBytes).Msg("forward log")
	}
}

type ForwardUserInfo struct {
	ValidTime  time.Time
	Username   string
	SpeedLimit int64
	VIP        bool
}

func (h *HTTPForwardHandler) GetAuthInfo(ri RequestInfo, req *http.Request) (ui ForwardUserInfo, err error) {
	var b bytes.Buffer

	err = h.AuthTemplate.Execute(&b, struct {
		Request         *http.Request
		ClientHelloInfo *tls.ClientHelloInfo
	}{req, ri.ClientHelloInfo})
	if err != nil {
		log.Error().Err(err).Str("forward_auth", h.Config.ForwardAuth).Msg("execute forward_auth error")
		return
	}

	commandLine := strings.TrimSpace(b.String())
	if v, ok := h.AuthCache.Get(commandLine); ok {
		ui = v.(ForwardUserInfo)
		if ui.ValidTime.After(timeNow()) {
			return
		}
		h.AuthCache.Delete(commandLine)
	}

	var command string
	var arguments []string
	command, arguments, err = SplitCommandLine(commandLine)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	b.Reset()
	cmd := exec.CommandContext(ctx, command, arguments...)
	cmd.Stdout = &b
	cmd.Stderr = &b

	err = cmd.Run()
	if err != nil {
		log.Warn().Strs("cmd_args", cmd.Args).Bytes("output", b.Bytes()).Str("remote_ip", ri.RemoteIP).Err(err).Msg("exec.Command(...) error")
		return
	}

	log.Debug().Str("remote_ip", ri.RemoteIP).Strs("cmd_args", cmd.Args).Bytes("output", b.Bytes()).Err(err).Msg("exec.Command() ok")

	var p fastjson.Parser
	var doc *fastjson.Value
	doc, err = p.ParseBytes(b.Bytes())
	if err != nil {
		return
	}

	if v := doc.GetStringBytes("username"); len(v) != 0 {
		ui.Username = string(v)
	}
	if v := doc.GetInt("speedlimit"); v > 0 {
		ui.SpeedLimit = int64(v)
	}
	if v := doc.GetInt("vip"); v != 0 {
		ui.VIP = true
	}
	if v := doc.GetStringBytes("error"); len(v) != 0 {
		err = errors.New(string(v))
	}
	if ttl := doc.GetInt("ttl"); ttl > 0 && err == nil {
		ui.ValidTime = timeNow().Add(time.Duration(ttl) * time.Second)
		h.AuthCache.Set(commandLine, ui)
	}

	return
}

func RejectRequest(rw http.ResponseWriter, req *http.Request) {
	time.Sleep(time.Duration(1+rand.Intn(3)) * time.Second)
	// http.Error(rw, "403 Forbidden", http.StatusForbidden)
	http.Error(rw, "400 Bad Request", http.StatusBadRequest)
}
