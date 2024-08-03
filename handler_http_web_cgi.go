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

	filename := req.URL.Path
	if strings.HasSuffix(filename, "/") {
		switch {
		case h.DefaultApp != "":
			filename += h.DefaultApp
		case h.phpcgi != "":
			filename += "index.php"
		default:
			filename += "index.cgi"
		}
	}

	filename = filepath.Join(h.Root, strings.TrimPrefix(req.URL.Path, filepath.Dir(h.Location)))

	log.Info().Context(ri.LogContext).Str("filename", filename).Msg("web cgi request")

	switch {
	case strings.HasSuffix(filename, ".php") && h.phpcgi != "":
		/*
			sudo apt install -y php-cgi
			echo '# for php-cgi
				cgi.rfc2616_headers = 1
				cgi.force_redirect = 0
				force_cgi_redirect = 0
			' | sudo tee /etc/php/?.?/cgi/conf.d/99-enable-headers.ini
		*/
		(&cgi.Handler{
			Path: h.phpcgi,
			Dir:  h.Root,
			Root: h.Root,
			Args: []string{filename},
			Env:  []string{"SCRIPT_FILENAME=" + filename},
		}).ServeHTTP(rw, req)
	case strings.HasSuffix(filename, ".cgi"):
		(&cgi.Handler{
			Path: filename,
			Root: h.Root,
			Env:  []string{"SCRIPT_FILENAME=" + filename},
		}).ServeHTTP(rw, req)
	default:
		fi, err := os.Stat(filename)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		if fi != nil && fi.IsDir() {
			index := filepath.Join(filename, "index.html")
			if fi, err = os.Stat(index); err == nil {
				filename = index
			}
		}
		http.ServeFile(rw, req, filename)
	}
}
