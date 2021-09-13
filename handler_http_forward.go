package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/template"
	"time"

	_ "github.com/mithrandie/csvq-driver"
	"github.com/phuslu/log"
	"golang.org/x/net/publicsuffix"
)

type HTTPForwardHandler struct {
	Config         HTTPConfig
	ForwardLogger  log.Logger
	RegionResolver *RegionResolver
	LocalDialer    *LocalDialer
	Transport      *http.Transport
	Upstreams      map[string]Dialer
	Functions      template.FuncMap

	allowDomains StringSet
	denyDomains  StringSet
	policy       *template.Template
	authDB       *sql.DB
	authTable    string
	upstream     *template.Template
	transports   map[string]*http.Transport
}

func (h *HTTPForwardHandler) Load() error {
	var err error

	expandDomains := func(domains []string) (a []string) {
		for _, s := range domains {
			switch {
			case strings.HasPrefix(s, "@"):
				data, err := os.ReadFile(s[1:])
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

	h.denyDomains = NewStringSet(expandDomains(h.Config.Forward.DenyDomains))

	if s := h.Config.Forward.Policy; s != "" {
		if h.policy, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	if s := h.Config.Forward.AuthDB; s != "" {
		u, err := url.Parse(h.Config.Forward.AuthDB)
		if err != nil {
			return err
		}
		switch u.Scheme {
		case "csvq":
			path, err := filepath.Abs(u.Path[1:])
			if err != nil {
				return err
			}
			if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
				h.authTable = filepath.Base(path)
				path = filepath.Dir(path)
			} else {
				h.authTable = "auth.csv"
			}
			h.authDB, err = sql.Open("csvq", path+"?"+u.RawQuery)
		default:
			err = fmt.Errorf("unsupported auth_db scheme: %s", u.Scheme)
		}
		if err != nil {
			return err
		}
	}

	if s := h.Config.Forward.Upstream; s != "" {
		if h.upstream, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	if len(h.Upstreams) != 0 {
		h.transports = make(map[string]*http.Transport)
		for name, dailer := range h.Upstreams {
			h.transports[name] = &http.Transport{
				DialContext:         dailer.DialContext,
				TLSClientConfig:     h.Transport.TLSClientConfig,
				TLSHandshakeTimeout: h.Transport.TLSHandshakeTimeout,
				IdleConnTimeout:     h.Transport.IdleConnTimeout,
				DisableCompression:  h.Transport.DisableCompression,
				MaxIdleConns:        32,
			}
		}
	}

	if h.Config.Forward.BindToDevice != "" {
		if runtime.GOOS != "linux" {
			log.Fatal().Strs("server_name", h.Config.ServerName).Msg("option bind_device is only available on linux")
		}
		if h.Config.Forward.Upstream != "" {
			log.Fatal().Strs("server_name", h.Config.ServerName).Msg("option bind_device is confilict with option upstream")
		}

		var dialer = *h.LocalDialer
		dialer.Control = (DailerController{BindToDevice: h.Config.Forward.BindToDevice}).Control

		h.Transport = &http.Transport{
			DialContext:         dialer.DialContext,
			TLSClientConfig:     h.Transport.TLSClientConfig,
			TLSHandshakeTimeout: h.Transport.TLSHandshakeTimeout,
			IdleConnTimeout:     h.Transport.IdleConnTimeout,
			MaxIdleConns:        h.Transport.MaxIdleConns,
			DisableCompression:  h.Transport.DisableCompression,
		}
	}

	return nil
}

func (h *HTTPForwardHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	var err error
	var host = req.Host
	if h, _, err := net.SplitHostPort(req.Host); err == nil {
		host = h
	}

	var domain = host
	if net.ParseIP(domain) == nil {
		if s, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
			domain = s
		}
	}

	if h.Config.Forward.Policy == "" {
		http.NotFound(rw, req)
		return
	}

	var bypassAuth bool

	var sb strings.Builder
	if h.policy != nil {
		sb.Reset()
		err = h.policy.Execute(&sb, struct {
			Request         *http.Request
			ClientHelloInfo *tls.ClientHelloInfo
		}{req, ri.ClientHelloInfo})
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Str("forward_policy", h.Config.Forward.Policy).Interface("client_hello_info", ri.ClientHelloInfo).Interface("tls_connection_state", req.TLS).Msg("execute forward_policy error")
			http.NotFound(rw, req)
			return
		}

		output := strings.TrimSpace(sb.String())
		log.Debug().Context(ri.LogContext).Interface("client_hello_info", ri.ClientHelloInfo).Interface("tls_connection_state", req.TLS).Str("forward_policy_output", output).Msg("execute forward_policy ok")

		switch output {
		case "", "proxy_pass":
			http.NotFound(rw, req)
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
				Body:          io.NopCloser(strings.NewReader(authText)),
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

	var ai ForwardAuthInfo
	if h.authDB != nil && !bypassAuth {
		ai, err = h.GetAuthInfo(ri, req)
		if err != nil {
			log.Warn().Err(err).Context(ri.LogContext).Str("username", ai.Username).Str("proxy_authorization", req.Header.Get("proxy-authorization")).Msg("auth error")
			RejectRequest(rw, req)
			return
		}
	}

	if ai.VIP > 0 {
		if !h.allowDomains.Empty() || !h.denyDomains.Empty() {
			if !h.allowDomains.Empty() && !h.allowDomains.Contains(domain) {
				RejectRequest(rw, req)
				return
			}
			if h.denyDomains.Contains(domain) {
				RejectRequest(rw, req)
				return
			}
		}
		if ai.SpeedLimit == 0 && h.Config.Forward.SpeedLimit > 0 {
			ai.SpeedLimit = h.Config.Forward.SpeedLimit
		}
	}

	var upstream = ""
	if h.upstream != nil {
		sb.Reset()
		err := h.upstream.Execute(&sb, struct {
			Request         *http.Request
			ClientHelloInfo *tls.ClientHelloInfo
			User            ForwardAuthInfo
		}{req, ri.ClientHelloInfo, ai})
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Str("forward_upstream", h.Config.Forward.Upstream).Msg("execute forward_upstream error")
			http.NotFound(rw, req)
			return
		}
		upstream = strings.TrimSpace(sb.String())
	}

	log.Info().Context(ri.LogContext).Str("username", ai.Username).Str("upstream", upstream).Str("http_domain", domain).Msg("forward request")

	var transmitBytes int64
	switch req.Method {
	case http.MethodConnect:
		if req.URL.Host == ri.ServerName {
			// FIXME: handle self-connect clients
		}

		var dialer Dialer
		if upstream != "" {
			if d, ok := h.Upstreams[upstream]; !ok {
				log.Error().Context(ri.LogContext).Str("upstream", upstream).Msg("no upstream exists")
				http.NotFound(rw, req)
				return
			} else {
				dialer = d
			}
		} else {
			dialer = h.LocalDialer
		}

		conn, err := dialer.DialContext(req.Context(), "tcp", req.URL.Host)
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Msg("dial host error")
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
		transmitBytes, err = io.Copy(w, NewLimiterReader(conn, ai.SpeedLimit))
		log.Debug().Context(ri.LogContext).Str("username", ai.Username).Str("http_domain", domain).Int64("transmit_bytes", transmitBytes).Err(err).Msg("forward log")
	default:
		if req.Host == "" {
			http.NotFound(rw, req)
			return
		}

		if req.URL.Host == "" {
			req.URL.Host = req.Host
		}

		if req.ContentLength == 0 {
			io.Copy(io.Discard, req.Body)
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

		var tr *http.Transport
		if upstream != "" {
			if t, ok := h.transports[upstream]; !ok {
				log.Error().Context(ri.LogContext).Str("upstream", upstream).Msg("no upstream transport exists")
				http.NotFound(rw, req)
				return
			} else {
				tr = t
			}
		} else {
			tr = h.Transport
		}

		resp, err := tr.RoundTrip(req)
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

		transmitBytes, err = io.Copy(rw, NewLimiterReader(resp.Body, ai.SpeedLimit))
		log.Debug().Context(ri.LogContext).Str("username", ai.Username).Str("http_domain", domain).Int64("transmit_bytes", transmitBytes).Err(err).Msg("forward log")
	}

	if h.Config.Forward.Log {
		var country, region, city string
		if h.RegionResolver.MaxmindReader != nil {
			country, region, city, _ = h.RegionResolver.LookupCity(context.Background(), net.ParseIP(ri.RemoteIP))
		} else {
			country, _ = h.RegionResolver.LookupCountry(context.Background(), ri.RemoteIP)
		}
		h.ForwardLogger.Info().Xid("trace_id", ri.TraceID).Str("server_name", ri.ServerName).Str("server_addr", ri.ServerAddr).Str("tls_version", ri.TLSVersion.String()).Str("username", ai.Username).Str("remote_ip", ri.RemoteIP).Str("remote_country", country).Str("remote_region", region).Str("remote_city", city).Str("http_method", req.Method).Str("http_host", host).Str("http_domain", domain).Str("http_proto", req.Proto).Str("user_agent", req.UserAgent()).Int64("transmit_bytes", transmitBytes).Msg("forward log")
	}
}

type ForwardAuthInfo struct {
	Username   string
	Password   string
	SpeedLimit int64
	VIP        int
}

func (h *HTTPForwardHandler) GetAuthInfo(ri *RequestInfo, req *http.Request) (ForwardAuthInfo, error) {
	authorization := req.Header.Get("proxy-authorization")
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) == 1 {
		return ForwardAuthInfo{}, fmt.Errorf("invaild auth header: %s", authorization)
	}
	if parts[0] != "Basic" {
		return ForwardAuthInfo{}, fmt.Errorf("unsupported auth header: %s", authorization)
	}

	data, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return ForwardAuthInfo{}, err
	}

	parts = strings.SplitN(string(data), ":", 2)
	if len(parts) == 1 {
		return ForwardAuthInfo{}, fmt.Errorf("invaild auth header: %s", authorization)
	}

	username, password := parts[0], parts[1]

	var ai ForwardAuthInfo
	err = h.authDB.QueryRow("SELECT username, password, speedlimit, vip FROM `"+h.authTable+"` WHERE username=? LIMIT 1", username).Scan(&ai.Username, &ai.Password, &ai.SpeedLimit, &ai.VIP)
	if err != nil {
		return ai, err
	}

	if ai.Password != password {
		return ai, fmt.Errorf("wrong username='%s' or password='%s'", username, password)
	}

	return ai, nil
}

func RejectRequest(rw http.ResponseWriter, req *http.Request) {
	time.Sleep(time.Duration(1+log.Fastrandn(3)) * time.Second)
	// http.Error(rw, "403 Forbidden", http.StatusForbidden)
	http.Error(rw, "400 Bad Request", http.StatusBadRequest)
}
