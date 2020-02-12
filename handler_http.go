package main

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
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

	h.Next.ServeHTTP(rw, req.WithContext(context.WithValue(req.Context(), RequestInfoContextKey, ri)))
}
