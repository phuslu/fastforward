package main

import (
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/phuslu/log"
)

type HTTPDoHHandler struct {
	Next      http.Handler
	Config    HTTPConfig
	Transport *http.Transport

	upstream *url.URL
}

func (h *HTTPDoHHandler) Load() (err error) {
	h.upstream, err = url.Parse(h.Config.Doh.Upstream)
	return
}

func (h *HTTPDoHHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	if req.TLS == nil {
		h.Next.ServeHTTP(rw, req)
		return
	}

	if !h.Config.Doh.Enabled || req.URL.Path != h.Config.Doh.Path {
		h.Next.ServeHTTP(rw, req)
		return
	}

	log.Info().Context(ri.LogContext).Msg("doh request")

	req.Host = h.upstream.Host
	req.URL.Host = h.upstream.Host
	req.URL.Path = h.upstream.Path
	req.URL.Scheme = h.upstream.Scheme
	resp, err := h.Transport.RoundTrip(req)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for key, values := range resp.Header {
		switch strings.ToLower(key) {
		case "server", "expect-ct", "cf-ray", "cf-request-id":
			continue
		}
		for _, value := range values {
			rw.Header().Add(key, value)
		}
	}
	rw.WriteHeader(resp.StatusCode)
	io.Copy(rw, resp.Body)
}
