package main

import (
	"context"
	"crypto/tls"
	_ "embed"
	"mime"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/phuslu/log"
)

type HTTPHandler interface {
	http.Handler
	Load() error
}

type HTTPServerHandler struct {
	Config          HTTPConfig
	TLSConfigurator *TLSConfigurator
	ServerNames     StringSet
	ForwardHandler  HTTPHandler
	TunnelHandler   HTTPHandler
	WebHandler      HTTPHandler
}

type RequestInfo struct {
	RemoteIP        string
	ServerAddr      string
	ServerName      string
	TLSVersion      TLSVersion
	ClientHelloInfo *tls.ClientHelloInfo
	ClientHelloRaw  []byte
	TraceID         log.XID
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
	if h.TLSConfigurator != nil {
		if v, ok := h.TLSConfigurator.ClientHelloCache.Get(req.RemoteAddr); ok {
			ri.ClientHelloInfo = v.(*tls.ClientHelloInfo)
			if header := GetMirrorHeader(ri.ClientHelloInfo.Conn); header != nil {
				ri.ClientHelloRaw = header.B
			}
		}
	}

	// fix http3 request
	if req.Proto == "" && ri.ClientHelloInfo != nil && len(ri.ClientHelloInfo.SupportedProtos) > 0 && ri.ClientHelloInfo.SupportedProtos[0] == "h3" {
		req.Proto, req.ProtoMajor, req.ProtoMinor = "HTTP/3.0", 3, 0
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
		Value()

	hostname := req.Host
	if h, _, err := net.SplitHostPort(req.Host); err == nil {
		hostname = h
	}

	req = req.WithContext(context.WithValue(req.Context(), RequestInfoContextKey, ri))
	if hostname != "" && !h.ServerNames.Contains(hostname) {
		h.ForwardHandler.ServeHTTP(rw, req)
	} else if h.ServerNames.Contains(hostname) && h.Config.Forward.Websocket != "" && req.URL.Path == h.Config.Forward.Websocket && ((req.Method == http.MethodGet && req.ProtoMajor == 1) || (req.Method == http.MethodConnect && req.ProtoAtLeast(2, 0))) {
		h.ForwardHandler.ServeHTTP(rw, req)
	} else {
		h.WebHandler.ServeHTTP(rw, req)
	}
}
