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
	type router struct {
		location string
		handler  HTTPHandler
	}

	var routers []router
	for _, web := range h.Config.Web {
		switch {
		case web.Pprof.Enabled:
			routers = append(routers, router{
				web.Location,
				&HTTPWebPprofHandler{
					AllowPublicNet: false,
				},
			})
		case web.Proxy.Pass != "":
			routers = append(routers, router{
				web.Location,
				&HTTPWebProxyHandler{
					Transport:         h.Transport,
					Functions:         h.Functions,
					Pass:              web.Proxy.Pass,
					AuthBasicUserFile: web.Proxy.AuthBasicUserFile,
					SetHeaders:        web.Proxy.SetHeaders,
					DumpFailure:       web.Proxy.DumpFailure,
				},
			})
		case web.Dav.Enabled:
			routers = append(routers, router{
				web.Location,
				&HTTPWebDavHandler{
					Root:              web.Dav.Root,
					AuthBasicUserFile: web.Dav.AuthBasicUserFile,
				},
			})
		case web.Index.Root != "" || web.Index.Body != "" || web.Index.File != "":
			routers = append(routers, router{
				web.Location,
				&HTTPWebIndexHandler{
					Functions: h.Functions,
					Root:      web.Index.Root,
					Headers:   web.Index.Headers,
					Body:      web.Index.Body,
					File:      web.Index.File,
				},
			})
		}
	}

	var root HTTPHandler
	var wildcards []router
	h.mux = http.NewServeMux()
	for _, x := range routers {
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
	if config, _ := h.Config.ServerConfig[req.Host]; !config.DisableHttp3 && req.ProtoMajor != 3 {
		_, port, _ := net.SplitHostPort(req.Context().Value(http.LocalAddrContextKey).(net.Addr).String())
		rw.Header().Add("Alt-Svc", `h3=":`+port+`"; ma=2592000,h3-29=":`+port+`"; ma=2592000`)
	}
	h.mux.ServeHTTP(rw, req)
}
