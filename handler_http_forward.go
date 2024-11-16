package main

import (
	"cmp"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/mileusna/useragent"
	"github.com/phuslu/log"
	"github.com/valyala/bytebufferpool"
	"golang.org/x/net/publicsuffix"
)

type HTTPForwardHandler struct {
	Config         HTTPConfig
	ForwardLogger  log.Logger
	LocalDialer    *LocalDialer
	LocalTransport *http.Transport
	Dialers        map[string]Dialer
	Functions      template.FuncMap

	policy        *template.Template
	tcpcongestion *template.Template
	dialer        *template.Template
	transports    map[string]*http.Transport
	csvloader     *FileLoader[[]UserInfo]
}

func (h *HTTPForwardHandler) Load() error {
	var err error

	h.Config.Forward.Policy = strings.TrimSpace(h.Config.Forward.Policy)
	if s := h.Config.Forward.Policy; strings.Contains(s, "{{") {
		if h.policy, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	h.Config.Forward.TcpCongestion = strings.TrimSpace(h.Config.Forward.TcpCongestion)
	if s := h.Config.Forward.TcpCongestion; strings.Contains(s, "{{") {
		if h.tcpcongestion, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	h.Config.Forward.Dialer = strings.TrimSpace(h.Config.Forward.Dialer)
	if s := h.Config.Forward.Dialer; strings.Contains(s, "{{") {
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

	if strings.HasSuffix(h.Config.Forward.AuthTable, ".csv") {
		h.csvloader = &FileLoader[[]UserInfo]{
			Filename:     h.Config.Forward.AuthTable,
			Unmarshal:    UserCsvUnmarshal,
			PollDuration: 15 * time.Second,
			ErrorLogger:  log.DefaultLogger.Std("", 0),
		}
		records := h.csvloader.Load()
		if records == nil {
			log.Fatal().Strs("server_name", h.Config.ServerName).Str("auth_table", h.Config.Forward.AuthTable).Msg("load auth_table failed")
		}
		log.Info().Strs("server_name", h.Config.ServerName).Str("auth_table", h.Config.Forward.AuthTable).Int("auth_table_size", len(*records)).Msg("load auth_table ok")
	}

	return nil
}

func (h *HTTPForwardHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	tunnel := strings.HasPrefix(req.URL.Path, HTTPTunnelConnectTCPPathPrefix)
	if tunnel {
		// see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-connect-tcp-05
		parts := strings.Split(req.URL.Path, "/")
		hostport := net.JoinHostPort(parts[len(parts)-3], parts[len(parts)-2])

		// fix up request
		req.Host = hostport
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

	if ri.ProxyUser.Username != "" && h.Config.Forward.AuthTable != "" {
		records := *h.csvloader.Load()
		i, ok := slices.BinarySearchFunc(records, ri.ProxyUser, func(a, b UserInfo) int { return cmp.Compare(a.Username, b.Username) })
		switch {
		case !ok:
			ri.ProxyUser.AuthError = fmt.Errorf("invalid username: %v", ri.ProxyUser.Username)
		case ri.ProxyUser.Password != records[i].Password:
			ri.ProxyUser.AuthError = fmt.Errorf("wrong password: %v", ri.ProxyUser.Username)
		default:
			ri.ProxyUser = records[i]
		}
	}

	bb := bytebufferpool.Get()
	defer bytebufferpool.Put(bb)

	policyName := h.Config.Forward.Policy
	speedLimit := h.Config.Forward.SpeedLimit
	if h.policy != nil {
		bb.Reset()
		err = h.policy.Execute(bb, struct {
			Request         *http.Request
			ClientHelloInfo *tls.ClientHelloInfo
			UserInfo        UserInfo
			UserAgent       *useragent.UserAgent
			ServerAddr      string
		}{req, ri.ClientHelloInfo, ri.ProxyUser, &ri.UserAgent, ri.ServerAddr})
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Str("forward_policy", h.Config.Forward.Policy).Interface("client_hello_info", ri.ClientHelloInfo).Interface("tls_connection_state", req.TLS).Msg("execute forward_policy error")
			http.NotFound(rw, req)
			return
		}

		policyName = strings.TrimSpace(bb.String())
		log.Debug().Context(ri.LogContext).Interface("client_hello_info", ri.ClientHelloInfo).Interface("tls_connection_state", req.TLS).Str("forward_policy_name", policyName).Msg("execute forward_policy ok")

		switch policyName {
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
			switch policyName {
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
		}
	}

	if policyName != "bypass_auth" && (ri.ProxyUser.Username == "" || ri.ProxyUser.AuthError != nil) {
		log.Warn().Err(err).Context(ri.LogContext).Str("username", ri.ProxyUser.Username).Str("proxy_authorization", req.Header.Get("proxy-authorization")).Msg("auth error")
		RejectRequest(rw, req)
		return
	}

	if s, _ := ri.ProxyUser.Attrs["allow_client"].(string); s != "" && s != "1" {
		browser := strings.HasPrefix(req.UserAgent(), "Mozilla/5.0 ")
		if ri.ClientHelloInfo != nil && len(ri.ClientHelloInfo.CipherSuites) != 0 {
			if c := ri.ClientHelloInfo.CipherSuites[0]; !(c&0x0f0f == 0x0a0a && c&0xff == c>>8) {
				browser = false
			}
		}
		if !browser {
			log.Warn().Err(err).Context(ri.LogContext).Str("username", ri.ProxyUser.Username).Str("proxy_authorization", req.Header.Get("proxy-authorization")).Msg("user is not allow client")
			RejectRequest(rw, req)
			return
		}
	}

	if s, _ := ri.ProxyUser.Attrs["speed_limit"].(string); s != "" {
		n, _ := strconv.ParseInt(s, 10, 64)
		switch {
		case n > 0:
			speedLimit = n
		case n < 0:
			speedLimit = 0 // no speed_limit
		}
	}

	// eval tcp_congestion template
	if ri.ClientTCPConn != nil && h.Config.Forward.TcpCongestion != "" {
		var tcpCongestion = h.Config.Forward.TcpCongestion
		if h.tcpcongestion != nil {
			bb.Reset()
			err := h.tcpcongestion.Execute(bb, struct {
				Request         *http.Request
				ClientHelloInfo *tls.ClientHelloInfo
				UserAgent       *useragent.UserAgent
				ServerAddr      string
				User            UserInfo
			}{req, ri.ClientHelloInfo, &ri.UserAgent, ri.ServerAddr, ri.ProxyUser})
			if err != nil {
				log.Error().Err(err).Context(ri.LogContext).Str("forward_tcp_congestion", h.Config.Forward.TcpCongestion).Msg("execute forward_tcp_congestion error")
				http.Error(rw, err.Error(), http.StatusBadGateway)
				return
			}
			tcpCongestion = bb.String()
		}
		if options := strings.Fields(tcpCongestion); len(options) >= 1 {
			switch name := options[0]; name {
			case "brutal":
				if len(options) < 2 {
					log.Error().Context(ri.LogContext).Strs("forward_tcp_congestion_options", options).Msg("parse forward_tcp_congestion error")
					http.Error(rw, err.Error(), http.StatusBadGateway)
					return
				}
				if rate, _ := strconv.Atoi(options[1]); rate > 0 {
					gain := 20 // hysteria2 default
					if len(options) >= 3 {
						if n, _ := strconv.Atoi(options[2]); n > 0 {
							gain = n
						}
					}
					if err := SetTcpCongestion(ri.ClientTCPConn, name, uint64(rate), uint32(gain)); err != nil {
						log.Error().Context(ri.LogContext).Strs("forward_tcp_congestion_options", options).Msg("set forward_tcp_congestion error")
						http.Error(rw, err.Error(), http.StatusBadGateway)
						return
					}
					log.Debug().Str("remote_ip", ri.RemoteIP).Strs("forward_tcp_congestion_options", options).Msg("set forward_tcp_congestion ok")
				}
			default:
				if err := SetTcpCongestion(ri.ClientTCPConn, name); err != nil {
					log.Error().Context(ri.LogContext).Strs("forward_tcp_congestion_options", options).Msg("set forward_tcp_congestion error")
					http.Error(rw, err.Error(), http.StatusBadGateway)
					return
				}
			}
		}
	}

	if ri.ClientTCPConn != nil && speedLimit > 0 {
		err := SetTcpMaxPacingRate(ri.ClientTCPConn, int(speedLimit))
		log.DefaultLogger.Err(err).Context(ri.LogContext).Int64("forward_speedlimit", speedLimit).Msg("set forward_speedlimit")
	}

	var dialerValue = h.Config.Forward.Dialer
	if h.dialer != nil {
		bb.Reset()
		err := h.dialer.Execute(bb, struct {
			Request         *http.Request
			ClientHelloInfo *tls.ClientHelloInfo
			UserAgent       *useragent.UserAgent
			ServerAddr      string
			User            UserInfo
		}{req, ri.ClientHelloInfo, &ri.UserAgent, ri.ServerAddr, ri.ProxyUser})
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("execute forward_dialer error")
			http.NotFound(rw, req)
			return
		}
		dialerValue = strings.TrimSpace(bb.String())
	}

	var userLog = h.Config.Forward.Log
	if ri.ProxyUser.Attrs["no_log"] == "1" {
		userLog = false
	}

	log.Info().Context(ri.LogContext).Str("req_method", req.Method).Str("req_host", req.Host).Any("req_header", req.Header).Str("username", ri.ProxyUser.Username).Any("user_attrs", ri.ProxyUser.Attrs).Str("forward_policy_name", policyName).Str("forward_dialer_value", dialerValue).Str("http_domain", domain).Int64("speed_limit", speedLimit).Msg("forward request")

	var dialerName = dialerValue
	var preferIPv6 = h.Config.Forward.PreferIpv6
	if strings.Contains(dialerValue, "=") {
		u, err := url.ParseQuery(dialerValue)
		if err != nil {
			log.Error().Context(ri.LogContext).Err(err).Str("username", ri.ProxyUser.Username).Str("forward_policy_name", policyName).Str("forward_dialer_value", dialerValue).Str("http_domain", domain).Msg("forward parse dialer json error")
			return
		}
		dialerName = u.Get("dialer")
		if s := u.Get("prefer_ipv6"); s != "" {
			preferIPv6, _ = strconv.ParseBool(s)
		}
	}

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

		ctx := req.Context()
		if preferIPv6 {
			ctx = context.WithValue(ctx, DialerPreferIPv6ContextKey, struct{}{})
		}
		if header, _ := ctx.Value(DialerHTTPHeaderContextKey).(http.Header); header != nil {
			if s := header.Get("x-forwarded-for"); s != "" {
				header.Set("x-forwarded-for", s+","+ri.RemoteIP)
			} else {
				header.Set("x-forwarded-for", ri.RemoteIP)
			}
			if s := header.Get("x-forwarded-user"); s != "" {
				header.Set("x-forwarded-user", s+","+ri.ProxyUser.Username)
			} else {
				header.Set("x-forwarded-user", ri.ProxyUser.Username)
			}
		} else {
			ctx = context.WithValue(ctx, DialerHTTPHeaderContextKey, http.Header{
				"x-forwarded-for":  []string{ri.RemoteIP},
				"x-forwarded-user": []string{ri.ProxyUser.Username},
			})
		}
		network := cmp.Or(req.Header.Get("x-forwarded-network"), "tcp")
		conn, err := dialer.DialContext(ctx, network, req.Host)
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Msg("dial host error")
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}

		log.Debug().Context(ri.LogContext).Any("req_header", req.Header).Stringer("conn_remote_addr", conn.RemoteAddr()).Msg("dial host ok")

		var w io.Writer
		var r io.Reader

		if req.ProtoAtLeast(2, 0) {
			flusher, ok := rw.(http.Flusher)
			if !ok {
				http.Error(rw, fmt.Sprintf("%#v is not http.Flusher", rw), http.StatusBadGateway)
				return
			}

			if tunnel && req.Header.Get("Sec-Websocket-Key") != "" {
				key := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				rw.Header().Set("sec-websocket-accept", base64.StdEncoding.EncodeToString(key[:]))
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

			if tunnel {
				key := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
				fmt.Fprintf(lconn, "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n", base64.StdEncoding.EncodeToString(key[:]))
			} else {
				io.WriteString(lconn, "HTTP/1.1 200 OK\r\n\r\n")
			}
		}

		defer conn.Close()

		go io.Copy(conn, r)

		if userLog {
			w = &ForwardLogWriter{
				Writer: w,
				Logger: h.ForwardLogger,
				Context: log.NewContext(nil).
					Xid("trace_id", ri.TraceID).
					Str("server_name", ri.ServerName).
					Str("server_addr", ri.ServerAddr).
					Str("tls_version", ri.TLSVersion.String()).
					Str("username", ri.ProxyUser.Username).
					Str("remote_ip", ri.RemoteIP).
					Str("remote_country", ri.GeoipInfo.Country).
					Str("remote_city", ri.GeoipInfo.City).
					Str("http_method", req.Method).
					Str("http_host", host).
					Str("http_domain", domain).
					Str("http_proto", req.Proto).
					Str("user_agent", req.UserAgent()).
					Str("user_agent_os", ri.UserAgent.OS).
					Str("user_agent_os_version", ri.UserAgent.OSVersion).
					Str("user_agent_name", ri.UserAgent.Name).
					Str("user_agent_version", ri.UserAgent.Version).
					Int64("speed_limit", speedLimit).
					Value(),
				FieldName: "transmit_bytes",
				Interval:  cmp.Or(h.Config.Forward.LogInterval, 1),
			}
		}
		transmitBytes, err := io.CopyBuffer(w, conn, make([]byte, 1024*1024)) // buffer size should align to http2.MaxReadFrameSize
		log.Debug().Context(ri.LogContext).Str("username", ri.ProxyUser.Username).Str("http_domain", domain).Int64("speed_limit", speedLimit).Int64("transmit_bytes", transmitBytes).Err(err).Msg("forward log")
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

		var w io.Writer = rw
		if userLog {
			w = &ForwardLogWriter{
				Writer: w,
				Logger: h.ForwardLogger,
				Context: log.NewContext(nil).
					Xid("trace_id", ri.TraceID).
					Str("server_name", ri.ServerName).
					Str("server_addr", ri.ServerAddr).
					Str("tls_version", ri.TLSVersion.String()).
					Str("username", ri.ProxyUser.Username).
					Str("remote_ip", ri.RemoteIP).
					Str("remote_country", ri.GeoipInfo.Country).
					Str("remote_city", ri.GeoipInfo.City).
					Str("http_method", req.Method).
					Str("http_host", host).
					Str("http_domain", domain).
					Str("http_proto", req.Proto).
					Str("user_agent", req.UserAgent()).
					Str("user_agent_os", ri.UserAgent.OS).
					Str("user_agent_os_version", ri.UserAgent.OSVersion).
					Str("user_agent_name", ri.UserAgent.Name).
					Str("user_agent_version", ri.UserAgent.Version).
					Int64("speed_limit", speedLimit).
					Value(),
				FieldName: "transmit_bytes",
				Interval:  cmp.Or(h.Config.Forward.LogInterval, 1),
			}
		}

		transmitBytes, err := io.CopyBuffer(w, resp.Body, make([]byte, 1024*1024)) // buffer size should align to http2.MaxReadFrameSize
		log.Debug().Context(ri.LogContext).Str("username", ri.ProxyUser.Username).Str("http_domain", domain).Int64("transmit_bytes", transmitBytes).Int64("speed_limit", speedLimit).Err(err).Msg("forward log")
	}
}

func UserCsvUnmarshal(data []byte, v any) error {
	infos, ok := v.(*[]UserInfo)
	if !ok {
		return fmt.Errorf("*[]UserInfo required, found %T", v)
	}
	lines := AppendSplitLines(nil, b2s(data))
	if len(lines) <= 1 {
		return fmt.Errorf("no csv rows: %s", data)
	}
	names := strings.Split(lines[0], ",")
	if len(names) <= 1 {
		return fmt.Errorf("no csv columns: %s", data)
	}
	for i := range names {
		names[i] = strings.ToLower(names[i])
	}
	for _, line := range lines[1:] {
		parts := strings.Split(line, ",")
		if len(parts) <= 1 {
			continue
		}
		var user UserInfo
		for i, part := range parts {
			switch i {
			case 0:
				user.Username = part
			case 1:
				user.Password = part
			default:
				if user.Attrs == nil {
					user.Attrs = make(map[string]any)
				}
				if i >= len(names) {
					return fmt.Errorf("overflow csv cloumn, names=%v parts=%v", names, parts)
				}
				user.Attrs[names[i]] = part
			}
		}
		*infos = append(*infos, user)
	}
	slices.SortFunc(*infos, func(a, b UserInfo) int {
		return cmp.Compare(a.Username, b.Username)
	})
	return nil
}

func RejectRequest(rw http.ResponseWriter, req *http.Request) {
	time.Sleep(time.Duration(1+fastrandn(3)) * time.Second)
	// http.Error(rw, "403 Forbidden", http.StatusForbidden)
	http.Error(rw, "400 Bad Request", http.StatusBadRequest)
}

type ForwardLogWriter struct {
	io.Writer
	Logger    log.Logger
	Context   log.Context
	FieldName string
	Interval  int64

	timestamp int64
	transmits int64
}

func (w *ForwardLogWriter) Write(buf []byte) (n int, err error) {
	n, err = w.Writer.Write(buf)
	now := time.Now().Unix()
	if w.transmits != 0 && (w.timestamp == 0 || now-w.timestamp >= w.Interval || err != nil) {
		w.Logger.Log().Context(w.Context).Int64(w.FieldName, w.transmits).Msg("forward log")
		w.timestamp = now
		w.transmits = 0
	} else {
		w.transmits += int64(n)
	}
	return
}
