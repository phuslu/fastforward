package main

import (
	"expvar"
	"net"
	"net/http"
	"net/http/pprof"
	"strings"
)

type HTTPPprofHandler struct {
	Next   http.Handler
	Config HTTPConfig
}

func (h *HTTPPprofHandler) Load() error {
	return nil
}

func (h *HTTPPprofHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !h.Config.PprofEnabled || !strings.HasPrefix(req.URL.Path, "/debug/") {
		h.Next.ServeHTTP(rw, req)
		return
	}

	if ip, _, _ := net.SplitHostPort(req.RemoteAddr); !IsReservedIP(net.ParseIP(ip)) {
		h.Next.ServeHTTP(rw, req)
		return
	}

	switch req.URL.Path {
	case "/debug/vars":
		expvar.Handler().ServeHTTP(rw, req)
	case "/debug/pprof/cmdline":
		pprof.Cmdline(rw, req)
	case "/debug/pprof/profile":
		pprof.Profile(rw, req)
	case "/debug/pprof/symbol":
		pprof.Symbol(rw, req)
	case "/debug/pprof/trace":
		pprof.Trace(rw, req)
	default:
		pprof.Index(rw, req)
	}
}
