package main

import (
	"net/http"
	"text/template"

	"github.com/phuslu/log"
)

type HTTPTunnelHandler struct {
	Config         HTTPConfig
	TunnelLogger   log.Logger
	RegionResolver *RegionResolver
	LocalDialer    *LocalDialer
	LocalTransport *http.Transport
	Dialers        map[string]Dialer
	Functions      template.FuncMap

	policy     *template.Template
	dialer     *template.Template
	transports map[string]*http.Transport
}

func (h *HTTPTunnelHandler) Load() error {
	return nil
}

func (h *HTTPTunnelHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)
	_ = ri
}
