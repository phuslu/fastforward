package main

import (
	"context"
	"crypto/rc4"
	"crypto/tls"
	_ "embed"
	"encoding/base64"
	"mime"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/mileusna/useragent"
	"github.com/phuslu/log"
	"github.com/puzpuzpuz/xsync/v3"
)

type HTTPHandler interface {
	http.Handler
	Load() error
}

type HTTPServerHandler struct {
	Config         HTTPConfig
	ServerNames    []string
	ClientHelloMap *xsync.MapOf[string, *tls.ClientHelloInfo]
	UserAgentMap   *CachingMap[string, useragent.UserAgent]
	GeoResolver    *GeoResolver
	ForwardHandler HTTPHandler
	TunnelHandler  HTTPHandler
	WebHandler     HTTPHandler
}

type UserInfo struct {
	Username  string
	Password  string
	Attrs     map[string]any
	AuthError error
}

type RequestInfo struct {
	RemoteIP        string
	ServerAddr      string
	ServerName      string
	TLSVersion      TLSVersion
	ClientHelloInfo *tls.ClientHelloInfo
	ClientHelloRaw  []byte
	ClientTCPConn   *net.TCPConn
	TraceID         log.XID
	UserAgent       useragent.UserAgent
	ProxyUser       UserInfo
	GeoipInfo       GeoipInfo
	LogContext      log.Context
}

var RequestInfoContextKey = struct {
	name string
}{"request-info"}

var riPool = sync.Pool{
	New: func() interface{} {
		return new(RequestInfo)
	},
}

const (
	HTTPTunnelEncryptedPathPrefix  = "/t/20151012/"
	HTTPTunnelConnectTCPPathPrefix = "/.well-known/masque/tcp/"
	HTTPTunnelReverseTCPPathPrefix = "/.well-known/reverse/tcp/"
)

func (h *HTTPServerHandler) Load() error {
	for ext, typ := range mimeTypes {
		mime.AddExtensionType(ext, typ)
	}
	return nil
}

func (h *HTTPServerHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := riPool.Get().(*RequestInfo)
	defer riPool.Put(ri)

	ri.RemoteIP, _, _ = net.SplitHostPort(req.RemoteAddr)
	ri.ServerAddr = req.Context().Value(http.LocalAddrContextKey).(net.Addr).String()
	if req.TLS != nil {
		ri.ServerName = req.TLS.ServerName
		ri.TLSVersion = TLSVersion(req.TLS.Version)
	} else {
		ri.ServerName = ""
		ri.TLSVersion = 0
	}

	ri.ClientHelloInfo, ri.ClientHelloRaw, ri.ClientTCPConn = nil, nil, nil
	if h.ClientHelloMap != nil {
		if v, ok := h.ClientHelloMap.Load(req.RemoteAddr); ok {
			ri.ClientHelloInfo = v
			if header := GetMirrorHeader(ri.ClientHelloInfo.Conn); header != nil {
				ri.ClientHelloRaw = header.B
			}
			if req.ProtoMajor <= 2 {
				conn := ri.ClientHelloInfo.Conn
				if c, ok := conn.(*tls.Conn); ok && c != nil {
					conn = c.NetConn()
				}
				if c, ok := conn.(*MirrorHeaderConn); ok && c != nil {
					conn = c.Conn
				}
				if tc, ok := conn.(*net.TCPConn); ok && tc != nil {
					ri.ClientTCPConn = tc
				}
			}
		}
	}

	// fix http3 request
	if req.Proto == "" && ri.ClientHelloInfo != nil && len(ri.ClientHelloInfo.SupportedProtos) > 0 && ri.ClientHelloInfo.SupportedProtos[0] == "h3" {
		req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/3.0", 3, 0
	}

	// fix real remote ip
	if xfr := req.Header.Get("x-forwarded-for"); xfr != "" {
		ri.RemoteIP = strings.Split(xfr, ",")[0]
	}

	ri.UserAgent, _, _ = h.UserAgentMap.Get(req.Header.Get("User-Agent"))
	if h.GeoResolver.CityReader != nil {
		ri.GeoipInfo.Country, ri.GeoipInfo.City, _ = h.GeoResolver.LookupCity(context.Background(), net.ParseIP(ri.RemoteIP))
	}

	ri.ProxyUser = UserInfo{}
	if s := req.Header.Get("proxy-authorization"); s != "" {
		switch t, s, _ := strings.Cut(s, " "); t {
		case "Basic":
			if b, err := base64.StdEncoding.DecodeString(s); err == nil {
				ri.ProxyUser.Username, ri.ProxyUser.Password, _ = strings.Cut(string(b), ":")
			}
		}
	}

	// decode encrypted url
	if strings.HasPrefix(req.URL.Path, HTTPTunnelEncryptedPathPrefix) {
		key, payload := req.URL.Path[3:len(HTTPTunnelEncryptedPathPrefix)-1], req.URL.Path[len(HTTPTunnelEncryptedPathPrefix):]
		if b, err := base64.StdEncoding.AppendDecode(make([]byte, 0, 1024), s2b(payload)); err == nil {
			if cipher, err := rc4.NewCipher(s2b(key)); err == nil {
				cipher.XORKeyStream(b, b)
				if u, err := url.Parse(b2s(b)); err == nil {
					req.URL = u
				}
			}
		}
	}

	ri.TraceID = log.NewXID()

	ri.LogContext = log.NewContext(ri.LogContext[:0]).
		Xid("trace_id", ri.TraceID).
		Str("server_name", ri.ServerName).
		Str("server_addr", ri.ServerAddr).
		Str("tls_version", ri.TLSVersion.String()).
		Str("remote_ip", ri.RemoteIP).
		Str("user_agent", req.UserAgent()).
		Str("http_method", req.Method).
		Str("http_proto", req.Proto).
		Str("http_host", req.Host).
		Str("http_url", req.URL.String()).
		Str("http_x_forwarded_for", req.Header.Get("x-forwarded-for")).
		Str("http_x_forwarded_user", req.Header.Get("x-forwarded-user")).
		Str("useragent_os", ri.UserAgent.OS+" "+ri.UserAgent.OSVersion).
		Str("useragent_browser", ri.UserAgent.Name+" "+ri.UserAgent.Version).
		Str("remote_country", ri.GeoipInfo.Country).
		Str("remote_city", ri.GeoipInfo.City).
		Value()

	hostname := req.Host
	if h, _, err := net.SplitHostPort(req.Host); err == nil {
		hostname = h
	}
	containsHostname := slices.Contains(h.ServerNames, hostname) ||
		slices.ContainsFunc(h.ServerNames, func(s string) bool { return s != "" && s[0] == '*' && strings.HasSuffix(hostname, s[1:]) })

	req = req.WithContext(context.WithValue(req.Context(), RequestInfoContextKey, ri))
	switch {
	case hostname != "" && !containsHostname:
		h.ForwardHandler.ServeHTTP(rw, req)
	case containsHostname && strings.HasPrefix(req.URL.Path, HTTPTunnelConnectTCPPathPrefix):
		h.ForwardHandler.ServeHTTP(rw, req)
	case containsHostname && h.Config.Tunnel.Enabled && strings.HasPrefix(req.URL.Path, HTTPTunnelReverseTCPPathPrefix):
		h.TunnelHandler.ServeHTTP(rw, req)
	case req.Method == http.MethodConnect && req.RequestURI[0] != '/':
		h.ForwardHandler.ServeHTTP(rw, req)
	default:
		h.WebHandler.ServeHTTP(rw, req)
	}
}
