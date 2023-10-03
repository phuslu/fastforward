package main

import (
	"net/http"
	"net/http/cgi"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/phuslu/log"
)

// see https://github.com/mattn/go-cgiserver/blob/master/cgiserver.go
type HTTPWebCgiHandler struct {
	Root       string
	DefaultApp string
	LangMap    map[string]string
	UseLangMap bool
}

func (h *HTTPWebCgiHandler) Load() (err error) {
	root := h.Root
	if root == "" {
		root = "/"
	}

	if h.LangMap == nil {
		h.LangMap = make(map[string]string)
	}

	if h.UseLangMap {
		h.LangMap[".cgi"], _ = exec.LookPath("perl")
		h.LangMap[".php"], _ = exec.LookPath("php-cgi")
	}

	return
}

func (h *HTTPWebCgiHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	log.Info().Context(ri.LogContext).Interface("headers", req.Header).Msg("web dav request")

	path := req.URL.Path
	var isCGI bool
	file := filepath.FromSlash(path)
	if len(file) > 0 && os.IsPathSeparator(file[len(file)-1]) {
		file = file[:len(file)-1]
	}
	ext := filepath.Ext(file)
	bin, isCGI := h.LangMap[ext]
	file = filepath.Join(h.Root, file)

	f, e := os.Stat(file)
	if e != nil || f.IsDir() {
		if len(h.DefaultApp) > 0 {
			file = h.DefaultApp
		}
		ext := filepath.Ext(file)
		bin, isCGI = h.LangMap[ext]
	}

	if isCGI {
		var cgih cgi.Handler
		if h.UseLangMap {
			cgih = cgi.Handler{
				Path: bin,
				Dir:  h.Root,
				Root: h.Root,
				Args: []string{file},
				Env:  []string{"SCRIPT_FILENAME=" + file},
			}
		} else {
			cgih = cgi.Handler{
				Path: file,
				Root: h.Root,
			}
		}
		cgih.ServeHTTP(rw, req)
	} else {
		if (f != nil && f.IsDir()) || file == "" {
			tmp := filepath.Join(file, "index.html")
			f, e = os.Stat(tmp)
			if e == nil {
				file = tmp
			}
		}
		http.ServeFile(rw, req, file)
	}
}
