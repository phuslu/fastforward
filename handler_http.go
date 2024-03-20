package main

import (
	"context"
	"crypto/tls"
	_ "embed"
	"mime"
	"net"
	"net/http"
	"regexp"
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
	ForwardHandler HTTPHandler
	WebHandler     HTTPHandler
}

type RequestInfo struct {
	RemoteIP        string
	ServerAddr      string
	ServerName      string
	TLSVersion      TLSVersion
	ClientHelloInfo *tls.ClientHelloInfo
	ClientHelloRaw  []byte
	TraceID         log.XID
	UserAgent       useragent.UserAgent
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

//go:embed mime.types
var mimeTypes string

func (h *HTTPServerHandler) Load() error {
	for _, m := range regexp.MustCompile(`(?m)(\S+)\s+(\S+)`).FindAllStringSubmatch(mimeTypes, -1) {
		mime.AddExtensionType(strings.ToLower("."+m[2]), m[1])
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

	ri.ClientHelloInfo, ri.ClientHelloRaw = nil, nil
	if h.ClientHelloMap != nil {
		if v, ok := h.ClientHelloMap.Load(req.RemoteAddr); ok {
			ri.ClientHelloInfo = v
			if header := GetMirrorHeader(ri.ClientHelloInfo.Conn); header != nil {
				ri.ClientHelloRaw = header.B
			}
		}
	}

	// fix http3 request
	if req.Proto == "" && ri.ClientHelloInfo != nil && len(ri.ClientHelloInfo.SupportedProtos) > 0 && ri.ClientHelloInfo.SupportedProtos[0] == "h3" {
		req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/3.0", 3, 0
	}

	ri.UserAgent, _, _ = h.UserAgentMap.Get(req.Header.Get("User-Agent"))

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
		Str("useragent_os", ri.UserAgent.OS+" "+ri.UserAgent.OSVersion).
		Str("useragent_browser", ri.UserAgent.Name+" "+ri.UserAgent.Version).
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
	case containsHostname && h.Config.Forward.Websocket != "" && req.URL.Path == h.Config.Forward.Websocket && ((req.Method == http.MethodGet && req.ProtoMajor == 1) || (req.Method == http.MethodConnect && req.ProtoAtLeast(2, 0))):
		h.ForwardHandler.ServeHTTP(rw, req)
	case req.Method == http.MethodConnect:
		h.ForwardHandler.ServeHTTP(rw, req)
	default:
		h.WebHandler.ServeHTTP(rw, req)
	}
}
