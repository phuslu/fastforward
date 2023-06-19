package main

import (
	"net"
	"net/http"
	"strings"
	"text/template"

	"github.com/bmatcuk/doublestar"
	"github.com/phuslu/log"
)

type HTTPWebHandler struct {
	Config    HTTPConfig
	Transport *http.Transport
	Functions template.FuncMap

	mux *http.ServeMux
}

func (h *HTTPWebHandler) Load() error {
	var handlers, wildcards []struct {
		location string
		handler  HTTPHandler
	}
	var root HTTPHandler
	for _, web := range h.Config.Web {
		switch {
		case web.Pac.Enabled:
			handlers = append(handlers, struct {
				location string
				handler  HTTPHandler
			}{
				web.Location,
				&HTTPWebPacHandler{
					Functions: h.Functions,
				},
			})
		case web.Doh.Enabled:
			handlers = append(handlers, struct {
				location string
				handler  HTTPHandler
			}{
				web.Location,
				&HTTPWebDoHHandler{
					Transport: h.Transport,
					Upstream:  web.Doh.Upstream,
					Prelude:   web.Doh.Prelude,
				},
			})
		case web.Pprof.Enabled:
			handlers = append(handlers, struct {
				location string
				handler  HTTPHandler
			}{
				web.Location,
				&HTTPWebPprofHandler{
					AllowPublicNet: false,
				},
			})
		case web.Proxy.Pass != "":
			handlers = append(handlers, struct {
				location string
				handler  HTTPHandler
			}{
				web.Location,
				&HTTPWebProxyHandler{
					Transport:   h.Transport,
					Functions:   h.Functions,
					Pass:        web.Proxy.Pass,
					SetHeaders:  web.Proxy.SetHeaders,
					DumpFailure: web.Proxy.DumpFailure,
				},
			})
		case web.Dav.Enabled:
			handlers = append(handlers, struct {
				location string
				handler  HTTPHandler
			}{
				web.Location,
				&HTTPWebDavHandler{
					Root:              web.Dav.Root,
					AuthBasic:         web.Dav.AuthBasic,
					AuthBasicUserFile: web.Dav.AuthBasicUserFile,
				},
			})
		case web.Index.Root != "" || web.Index.Body != "":
			handlers = append(handlers, struct {
				location string
				handler  HTTPHandler
			}{
				web.Location,
				&HTTPWebIndexHandler{
					Functions: h.Functions,
					Root:      web.Index.Root,
					Headers:   web.Index.Headers,
					Body:      web.Index.Body,
				},
			})
		}
	}

	h.mux = http.NewServeMux()
	for _, x := range handlers {
		err := x.handler.Load()
		if err != nil {
			log.Fatal().Err(err).Str("web_location", x.location).Msgf("%T.Load() return error: %+v", x.handler, err)
		}
		log.Info().Str("web_location", x.location).Msgf("%T.Load() ok", x.handler)

		if x.location == "/" {
			root = x.handler
			continue
		}

		if strings.ContainsAny(x.location, "*?[]") {
			wildcards = append(wildcards, x)
			continue
		}

		h.mux.Handle(x.location, x.handler)
	}

	h.mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		for _, x := range wildcards {
			if ok, _ := doublestar.Match(x.location, req.URL.Path); ok {
				x.handler.ServeHTTP(rw, req)
				return
			}
		}

		if root != nil {
			root.ServeHTTP(rw, req)
			return
		}

		http.NotFound(rw, req)
	})

	return nil
}

func (h *HTTPWebHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	_, port, _ := net.SplitHostPort(req.Context().Value(http.LocalAddrContextKey).(net.Addr).String())
	rw.Header().Add("Alt-Svc", `h3=":`+port+`"; ma=2592000,h3-29=":`+port+`"; ma=2592000`)
	h.mux.ServeHTTP(rw, req)
}
