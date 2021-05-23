package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/phuslu/log"
	"golang.org/x/net/webdav"
)

type HTTPWebDavHandler struct {
	Root string

	webdav *webdav.Handler
}

func (h *HTTPWebDavHandler) Load() (err error) {
	h.Root = strings.TrimRight(h.Root, "/")

	h.webdav = &webdav.Handler{
		FileSystem: webdav.Dir("/"),
		LockSystem: webdav.NewMemLS(),
	}

	return
}

func (h *HTTPWebDavHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	log.Info().Context(ri.LogContext).Interface("headers", req.Header).Msg("web dav request")

	davfile := filepath.Join(h.Root, ".davpasswd")
	if err := HtpasswdVerify(davfile, req); err != nil && !os.IsNotExist(err) {
		log.Error().Context(ri.LogContext).Err(err).Msg("webdav auth error")
		rw.Header().Set("www-authenticate", `Basic realm="Authentication Required"`)
		http.Error(rw, "401 unauthorised: "+err.Error(), http.StatusUnauthorized)
		return
	}

	h.webdav.ServeHTTP(rw, req)

	return
}
