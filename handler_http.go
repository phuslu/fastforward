package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/phuslu/log"
	"github.com/rs/xid"
)

type HTTPHandler struct {
	Next http.Handler

	TLSConfigurator *TLSConfigurator
}

type RequestInfo struct {
	RemoteIP        string
	ServerAddr      string
	ServerName      string
	TLSVersion      TLSVersion
	ClientHelloInfo *tls.ClientHelloInfo
	TraceID         xid.ID
	LogContext      log.Context
}

var RequestInfoContextKey = struct {
	name string
}{"request-info"}

func (h *HTTPHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	var ri RequestInfo

	ri.RemoteIP, _, _ = net.SplitHostPort(req.RemoteAddr)
	ri.ServerAddr = req.Context().Value(http.LocalAddrContextKey).(net.Addr).String()
	if req.TLS != nil {
		ri.ServerName = req.TLS.ServerName
		ri.TLSVersion = TLSVersion(req.TLS.Version)
	}

	if h.TLSConfigurator != nil && h.TLSConfigurator.ClientHelloCache != nil {
		if v, ok := h.TLSConfigurator.ClientHelloCache.Get(req.RemoteAddr); ok {
			ri.ClientHelloInfo = v.(*tls.ClientHelloInfo)
		}
	}
	ri.TraceID = xid.New()

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

	h.Next.ServeHTTP(rw, req.WithContext(context.WithValue(req.Context(), RequestInfoContextKey, ri)))
}
