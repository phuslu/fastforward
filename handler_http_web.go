package main

import (
	"net/http"
	"text/template"

	"github.com/phuslu/log"
)

type HTTPWebHandler struct {
	Config    HTTPConfig
	Functions template.FuncMap

	mux *http.ServeMux
}

func (h *HTTPWebHandler) Load() error {
	handlers := make(map[string]HTTPHandler)
	handlers[h.Config.Web[0].Location] = &HTTPWebIndexHandler{
		Functions:    h.Functions,
		Root:         h.Config.Web[0].Index.Root,
		Headers:      h.Config.Web[0].Index.Headers,
		Body:         h.Config.Web[0].Index.Body,
		AddAfterBody: h.Config.Web[0].Index.AddAfterBody,
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
