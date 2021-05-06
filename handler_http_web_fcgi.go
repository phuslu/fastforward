package main

import (
	"net/http"

	"github.com/phuslu/log"
	"github.com/yookoala/gofast"
)

type HTTPWebFcgiHandler struct {
	Root   string
	Pass   string
	Params map[string]string

	connFactory gofast.ConnFactory
}

func (h *HTTPWebFcgiHandler) Load() error {
	h.connFactory = gofast.SimpleConnFactory("tcp", h.Pass)

	return nil
}

func (h *HTTPWebFcgiHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	log.Debug().Context(ri.LogContext).Interface("headers", req.Header).Msg("web fcgi request")

	gofast.NewHandler(
		gofast.NewFileEndpoint(h.Root+req.URL.Path)(gofast.BasicSession),
		gofast.SimpleClientFactory(h.connFactory),
	).ServeHTTP(rw, req)
}
