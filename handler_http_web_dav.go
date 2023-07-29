package main

import (
	"crypto/tls"
	"net/http"
	"os"

	"github.com/phuslu/log"
	"golang.org/x/net/webdav"
)

type HTTPWebDavHandler struct {
	Root              string
	AuthBasic         string
	AuthBasicUserFile string

	dav *webdav.Handler
}

func (h *HTTPWebDavHandler) Load() (err error) {
	root := h.Root
	if root == "" {
		root = "/"
	}

	h.dav = &webdav.Handler{
		FileSystem: webdav.Dir(root),
		LockSystem: webdav.NewMemLS(),
	}

	return
}

func (h *HTTPWebDavHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := GetRequestInfo(req)

	if ri.ClientHelloInfo != nil {
		conn := ri.ClientHelloInfo.Conn
		if c, ok := conn.(*tls.Conn); ok && c != nil {
			conn = c.NetConn()
		}
		if c, ok := conn.(interface {
			SetWriteBuffer(bytes int) error
		}); ok {
			c.SetWriteBuffer(1024 * 1024 * 1024)
		}
	}

	log.Info().Context(ri.LogContext).Interface("headers", req.Header).Msg("web dav request")

	if h.AuthBasicUserFile != "" {
		if err := HtpasswdVerify(h.AuthBasicUserFile, req); err != nil && !os.IsNotExist(err) {
			log.Error().Context(ri.LogContext).Err(err).Msg("web dav auth error")
			rw.Header().Set("www-authenticate", `Basic realm="`+h.AuthBasic+`"`)
			http.Error(rw, "401 unauthorised: "+err.Error(), http.StatusUnauthorized)

			return
		}
	}

	h.dav.ServeHTTP(rw, req)
}
