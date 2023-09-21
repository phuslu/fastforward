package main

import (
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/mileusna/useragent"
	"github.com/phuslu/log"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/net/publicsuffix"
)

type HTTPForwardHandler struct {
	Config         HTTPConfig
	ForwardLogger  log.Logger
	RegionResolver *RegionResolver
	LocalDialer    *LocalDialer
	LocalTransport *http.Transport
	Dialers        map[string]Dialer
	Functions      template.FuncMap

	policy     *template.Template
	dialer     *template.Template
	transports map[string]*http.Transport
}

func (h *HTTPForwardHandler) Load() error {
	var err error

	if s := h.Config.Forward.Policy; s != "" {
		if h.policy, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	if s := h.Config.Forward.Dialer; s != "" {
		if h.dialer, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	if len(h.Dialers) != 0 {
		h.transports = make(map[string]*http.Transport)
		for name, dailer := range h.Dialers {
			h.transports[name] = &http.Transport{
				DialContext:         dailer.DialContext,
				TLSClientConfig:     h.LocalTransport.TLSClientConfig,
				TLSHandshakeTimeout: h.LocalTransport.TLSHandshakeTimeout,
				IdleConnTimeout:     h.LocalTransport.IdleConnTimeout,
				DisableCompression:  h.LocalTransport.DisableCompression,
				MaxIdleConns:        32,
			}
		}
	}

	if h.Config.Forward.BindInterface != "" {
		if runtime.GOOS != "linux" {
			log.Fatal().Strs("server_name", h.Config.ServerName).Msg("option bind_device is only available on linux")
		}
		if h.Config.Forward.Dialer != "" {
			log.Fatal().Strs("server_name", h.Config.ServerName).Msg("option bind_device is confilict with option dialer")
		}

		dialer := new(LocalDialer)
		*dialer = *h.LocalDialer
		dialer.BindInterface = h.Config.Forward.BindInterface
		dialer.PreferIPv6 = h.Config.Forward.PreferIpv6

		h.LocalDialer = dialer
		h.LocalTransport = &http.Transport{
			DialContext:         dialer.DialContext,
			TLSClientConfig:     h.LocalTransport.TLSClientConfig,
			TLSHandshakeTimeout: h.LocalTransport.TLSHandshakeTimeout,
			IdleConnTimeout:     h.LocalTransport.IdleConnTimeout,
			MaxIdleConns:        h.LocalTransport.MaxIdleConns,
			DisableCompression:  h.LocalTransport.DisableCompression,
		}
	}

	return nil
}

func (h *HTTPForwardHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	websocket := h.Config.Forward.Websocket != "" && req.URL.Path == h.Config.Forward.Websocket && ((req.Method == http.MethodGet && req.ProtoMajor == 1) || (req.Method == http.MethodConnect && req.ProtoAtLeast(2, 0)))
	if websocket {
		host, port := req.URL.Query().Get("host"), req.URL.Query().Get("port")
		if host == "" && port == "" {
			host, port = req.URL.Query().Get("h"), req.URL.Query().Get("p")
		}
		req.Host = net.JoinHostPort(host, port)
		req.URL = &url.URL{Host: req.Host}
		req.Method = http.MethodConnect
	}

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
			UserAgent       *useragent.UserAgent
			ServerAddr      string
		}{req, ri.ClientHelloInfo, &ri.UserAgent, ri.ServerAddr})
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
	if h.Config.Forward.AuthTable != "" && !bypassAuth {
		ai, err = h.GetAuthInfo(ri, req)
		if err != nil {
			log.Warn().Err(err).Context(ri.LogContext).Str("username", ai.Username).Str("proxy_authorization", req.Header.Get("proxy-authorization")).Msg("auth error")
			RejectRequest(rw, req)
			return
		}
	}

	if ai.VIP == 0 {
		if ai.SpeedLimit == 0 && h.Config.Forward.SpeedLimit > 0 {
			ai.SpeedLimit = h.Config.Forward.SpeedLimit
		}
	}

	var dialerName = ""
	if h.dialer != nil {
		sb.Reset()
		err := h.dialer.Execute(&sb, struct {
			Request         *http.Request
			ClientHelloInfo *tls.ClientHelloInfo
			UserAgent       *useragent.UserAgent
			ServerAddr      string
			User            ForwardAuthInfo
		}{req, ri.ClientHelloInfo, &ri.UserAgent, ri.ServerAddr, ai})
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("execute forward_dialer error")
			http.NotFound(rw, req)
			return
		}
		dialerName = strings.TrimSpace(sb.String())
	}

	log.Info().Context(ri.LogContext).Str("username", ai.Username).Str("dialer_name", dialerName).Str("http_domain", domain).Msg("forward request")

	var transmitBytes int64
	switch req.Method {
	case http.MethodConnect:
		if req.URL.Host == ri.ServerName {
			// FIXME: handle self-connect clients
		}

		var dialer Dialer
		if dialerName != "" {
			if d, ok := h.Dialers[dialerName]; !ok {
				log.Error().Context(ri.LogContext).Str("dialer", dialerName).Msg("no dialer exists")
				http.NotFound(rw, req)
				return
			} else {
				dialer = d
			}
		} else {
			dialer = h.LocalDialer
		}

		conn, err := dialer.DialContext(req.Context(), "tcp", req.Host)
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

			if websocket {
				key := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				rw.Header().Set("sec-websocket-accept", string(key[:]))
				rw.Header().Set("upgrade", "websocket")
				rw.Header().Set("connection", "Upgrade")
				rw.WriteHeader(http.StatusSwitchingProtocols)
			} else {
				rw.WriteHeader(http.StatusOK)
			}
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

			if websocket {
				key := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				fmt.Fprintf(lconn, "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", key[:])
			} else {
				io.WriteString(lconn, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
			}
		}

		defer conn.Close()

		go io.Copy(conn, r)
		transmitBytes, err = io.CopyBuffer(w, NewRateLimitReader(conn, ai.SpeedLimit), make([]byte, 1024*1024)) // buffer size should align to http2.MaxReadFrameSize
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
		if dialerName != "" {
			if t, ok := h.transports[dialerName]; !ok {
				log.Error().Context(ri.LogContext).Str("dialer", dialerName).Msg("no dialer transport exists")
				http.NotFound(rw, req)
				return
			} else {
				tr = t
			}
		} else {
			tr = h.LocalTransport
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
		rw.Header().Set("connection", "close")

		rw.WriteHeader(resp.StatusCode)
		defer resp.Body.Close()

		transmitBytes, err = io.CopyBuffer(rw, NewRateLimitReader(resp.Body, ai.SpeedLimit), make([]byte, 1024*1024)) // buffer size should align to http2.MaxReadFrameSize
		log.Debug().Context(ri.LogContext).Str("username", ai.Username).Str("http_domain", domain).Int64("transmit_bytes", transmitBytes).Err(err).Msg("forward log")
	}

	if h.Config.Forward.Log {
		var country, region, city string
		if h.RegionResolver.MaxmindReader != nil {
			country, region, city, _ = h.RegionResolver.LookupCity(context.Background(), net.ParseIP(ri.RemoteIP))
		}
		h.ForwardLogger.Info().Xid("trace_id", ri.TraceID).Str("server_name", ri.ServerName).Str("server_addr", ri.ServerAddr).Str("tls_version", ri.TLSVersion.String()).Str("username", ai.Username).Str("remote_ip", ri.RemoteIP).Str("remote_country", country).Str("remote_region", region).Str("remote_city", city).Str("http_method", req.Method).Str("http_host", host).Str("http_domain", domain).Str("http_proto", req.Proto).Str("user_agent", req.UserAgent()).Str("user_agent_os", ri.UserAgent.OS).Str("user_agent_os_version", ri.UserAgent.OSVersion).Str("user_agent_name", ri.UserAgent.Name).Str("user_agent_version", ri.UserAgent.Version).Int64("transmit_bytes", transmitBytes).Msg("forward log")
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
	if strings.HasSuffix(h.Config.Forward.AuthTable, ".csv") {
		data, err := os.ReadFile(h.Config.Forward.AuthTable)
		if err != nil {
			return ai, err
		}
		records, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
		if err != nil {
			return ai, err
		}
		if len(records) < 2 || len(records[0]) < 4 || !(records[0][0] == "username" && records[0][1] == "password" && records[0][2] == "speedlimit" && records[0][3] == "vip") {
			return ai, fmt.Errorf("invaild csv records")
		}
		for _, record := range records[1:] {
			if record[0] != username {
				continue
			}
			ai.Username = record[0]
			ai.Password = record[1]
			ai.SpeedLimit, _ = strconv.ParseInt(record[2], 10, 64)
			ai.VIP, _ = strconv.Atoi(record[3])
		}
	} else {
		return ai, fmt.Errorf("unsupported auth_table: %s", h.Config.Forward.AuthTable)
	}

	switch {
	case strings.HasPrefix(ai.Password, "$2a$"):
		err = bcrypt.CompareHashAndPassword([]byte(ai.Password), []byte(password))
	default:
		if ai.Password != password {
			err = fmt.Errorf("plain password mismatch")
		}
	}

	if err != nil || ai.Username == "" {
		return ai, fmt.Errorf("wrong username='%s' or password='%s'", username, password)
	}

	return ai, nil
}

func RejectRequest(rw http.ResponseWriter, req *http.Request) {
	time.Sleep(time.Duration(1+log.Fastrandn(3)) * time.Second)
	// http.Error(rw, "403 Forbidden", http.StatusForbidden)
	http.Error(rw, "400 Bad Request", http.StatusBadRequest)
}
