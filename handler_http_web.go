package main

import (
	"net/http"
	"text/template"
)

type HTTPWebHandler struct {
	Config    HTTPConfig
	Functions template.FuncMap

	mux *http.ServeMux
}

func (h *HTTPWebHandler) Load() error {
	h.mux = http.NewServeMux()
	h.mux.Handle("/", &HTTPWebRootHandler{
		Config:    h.Config,
		Root:      h.Config.Web.Root,
		Functions: h.Functions,
	})

	return nil
}

func (h *HTTPWebHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	h.mux.ServeHTTP(rw, req)
}
