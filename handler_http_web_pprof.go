package main

import (
	"expvar"
	"net"
	"net/http"
	"net/http/pprof"
	"strings"
)

type HTTPWebPprofHandler struct {
	Next   http.Handler
	Config HTTPConfig
}

func (h *HTTPWebPprofHandler) Load() error {
	return nil
}

func (h *HTTPWebPprofHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !h.Config.Pprof.Enabled || !strings.HasPrefix(req.URL.Path, "/debug/") {
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
