package main

import (
	"errors"
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/phuslu/log"
)

type HTTPWebCgiHandler struct {
	Location   string
	Root       string
	DefaultApp string

	phpcgi string
}

func (h *HTTPWebCgiHandler) Load() (err error) {
	root := h.Root
	if root == "" {
		return errors.New("empty cgi root")
	}

	if strings.HasSuffix(h.Location, ".php") {
		h.phpcgi, err = exec.LookPath("php-cgi")
		if err != nil {
			return err
		}
	}

	return
}

func (h *HTTPWebCgiHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	var fullname string
	if strings.TrimRight(req.URL.Path, "/") == strings.TrimRight(h.Location, "/") && h.DefaultApp != "" {
		fullname = h.DefaultApp
		if !strings.HasPrefix(fullname, "/") {
			fullname = filepath.Join(h.Root, fullname)
		}
	}

	if fullname == "" {
		fullname = filepath.Join(h.Root, strings.TrimPrefix(req.URL.Path, h.Location))
	}

	log.Info().Context(ri.LogContext).Str("fullname", fullname).Msg("web cgi request")

	if strings.HasSuffix(fullname, ".php") && h.phpcgi != "" {
		/*
			/etc/php/8.1/cgi/conf.d/99-enable-headers.ini

				cgi.rfc2616_headers = 1
				cgi.force_redirect = 0
				force_cgi_redirect = 0
		*/
		(&cgi.Handler{
			Path: h.phpcgi,
			Dir:  h.Root,
			Root: h.Root,
			Args: []string{fullname},
			Env:  []string{"SCRIPT_FILENAME=" + fullname},
		}).ServeHTTP(rw, req)
		return
	}

	if strings.HasSuffix(fullname, ".cgi") {
		(&cgi.Handler{
			Path: fullname,
			Root: h.Root,
			Env:  []string{"SCRIPT_FILENAME=" + fullname},
		}).ServeHTTP(rw, req)
		return
	}

	fi, err := os.Stat(fullname)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	if fi != nil && fi.IsDir() {
		index := filepath.Join(fullname, "index.html")
		fi, err = os.Stat(index)
		if err == nil {
			fullname = index
		}
	}
	http.ServeFile(rw, req, fullname)
}
