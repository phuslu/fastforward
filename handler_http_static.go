package main

import (
	"bytes"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"text/template"

	"github.com/phuslu/log"
)

const defaultStaticTemplate = `<html>
<head><title>Index of {{.Request.URL.Path}}</title></head>
<body>
<h1>Index of {{.Request.URL.Path}}</h1><hr><pre><a href="../">../</a>
{{range .FileInfos -}}
{{if .IsDir -}}
<a href="{{.Name}}/">{{.Name}}/</a>                                                                        {{.ModTime.Format "02-Jan-2006 15:04"}}       -
{{else -}}
<a href="{{.Name}}">{{.Name}}</a>                                                                        {{.ModTime.Format "02-Jan-2006 15:04"}}    {{.Size}}
{{end -}}
{{end}}</pre><hr></body>
</html>
`

type HTTPStaticHandler struct {
	Next      http.Handler
	Config    HTTPConfig
	Functions template.FuncMap

	index    string
	charset  string
	template *template.Template
}

func (h *HTTPStaticHandler) Load() error {
	h.charset = h.Config.StaticCharset
	if h.charset == "" {
		h.charset = "utf-8"
	}

	h.index = h.Config.StaticIndex
	if h.index == "" {
		h.index = "index.html"
	}

	s := h.Config.StaticTemplate
	if s == "" {
		s = defaultStaticTemplate
	}

	tmpl, err := template.New(s).Funcs(h.Functions).Parse(s)
	if err != nil {
		return err
	}

	h.template = tmpl

	return nil
}

func (h *HTTPStaticHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	if h.Config.StaticRoot == "" {
		if h.Config.StaticTemplate != "" {
			for key, value := range h.Config.StaticAddHeaders {
				rw.Header().Add(key, value)
			}
			h.template.Execute(rw, struct {
				Request   *http.Request
				FileInfos []os.FileInfo
			}{req, nil})
		} else {
			h.Next.ServeHTTP(rw, req)
		}
		return
	}

	fullname := filepath.Join(h.Config.StaticRoot, req.URL.Path)

	fi, err := os.Stat(fullname)
	if err != nil {
		http.Error(rw, "404 not found", http.StatusNotFound)
		return
	}

	if fi.IsDir() {
		index := filepath.Join(fullname, h.index)
		if fi2, err := os.Stat(index); err == nil && !fi2.IsDir() {
			fullname = index
			fi = fi2
		}
	}

	if !fi.IsDir() {
		file, err := os.Open(fullname)
		if err != nil {
			http.Error(rw, "500 internal server error", http.StatusInternalServerError)
			return
		}
		defer file.Close()

		if s := mime.TypeByExtension(filepath.Ext(fullname)); s != "" {
			rw.Header().Set("content-type", s)
		} else {
			rw.Header().Set("content-type", "application/octet-stream")
		}

		for key, value := range h.Config.StaticAddHeaders {
			rw.Header().Add(key, value)
		}
		n, err := io.Copy(rw, file)

		log.Info().Context(ri.LogContext).Int("http_status", http.StatusOK).Int64("http_content_length", n).Msg("static_root request")

		return
	}

	infos, err := ioutil.ReadDir(fullname)
	if err != nil {
		http.Error(rw, "500 internal server error", http.StatusInternalServerError)
		return
	}

	infos2 := make([]os.FileInfo, 0, len(infos))
	for i := range []int{0, 1} {
		for _, info := range infos {
			switch {
			case info.Name()[0] == '.':
				continue
			case i == 0 && !info.IsDir():
				continue
			case i == 1 && info.IsDir():
				continue
			}
			infos2 = append(infos2, info)
		}
	}

	var b bytes.Buffer
	err = h.template.Execute(&b, struct {
		Request   *http.Request
		FileInfos []os.FileInfo
	}{req, infos2})
	if err != nil {
		http.Error(rw, "500 internal server error", http.StatusInternalServerError)
		return
	}

	// see https://phus.lu/autoindex.html
	if addFile := h.Config.StaticAddAfterBody; addFile != "" {
		if data, err := ioutil.ReadFile(filepath.Join(h.Config.StaticRoot, addFile)); err == nil {
			b.Write(data)
		}
	}

	rw.Header().Set("content-type", "text/html;charset="+h.charset)
	rw.Write(b.Bytes())
	return
}
