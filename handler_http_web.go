package main

import (
	"net/http"
	"text/template"

	"github.com/phuslu/log"
)

type HTTPWebHandler struct {
	Config    HTTPConfig
	Transport *http.Transport
	Functions template.FuncMap

	mux *http.ServeMux
}

func (h *HTTPWebHandler) Load() error {
	handlers := make(map[string]HTTPHandler)
	for _, web := range h.Config.Web {
		switch {
		case web.Pac.Enabled:
			handlers[web.Location] = &HTTPWebPacHandler{
				Functions: h.Functions,
			}
		case web.Doh.Enabled:
			handlers[web.Location] = &HTTPWebDoHHandler{
				Transport: h.Transport,
				Upstream:  web.Doh.Upstream,
				Prelude:   web.Doh.Prelude,
			}
		case web.Pprof.Enabled:
			handlers[web.Location] = &HTTPWebPprofHandler{
				AllowPublicNet: false,
			}
		case web.Proxy.Pass != "":
			handlers[web.Location] = &HTTPWebProxyHandler{
				Transport:   h.Transport,
				Functions:   h.Functions,
				Pass:        web.Proxy.Pass,
				SetHeaders:  web.Proxy.SetHeaders,
				DumpFailure: web.Proxy.DumpFailure,
			}
		case web.Index.Root != "" || web.Index.Body != "":
			handlers[web.Location] = &HTTPWebIndexHandler{
				Functions: h.Functions,
				Root:      web.Index.Root,
				Headers:   web.Index.Headers,
				Body:      web.Index.Body,
			}
		}
	}

	h.mux = http.NewServeMux()
	for prefix, handler := range handlers {
		err := handler.Load()
		if err != nil {
			log.Fatal().Err(err).Str("web_prefix", prefix).Msgf("%T.Load() return error: %+v", h, err)
		}
		log.Info().Str("web_prefix", prefix).Msgf("%T.Load() ok", h)
		h.mux.Handle(prefix, handler)
	}

	return nil
}

func (h *HTTPWebHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	h.mux.ServeHTTP(rw, req)
}
