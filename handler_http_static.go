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

	charset  string
	template *template.Template
}

func (h *HTTPStaticHandler) Load() error {
	h.charset = h.Config.StaticCharset
	if h.charset == "" {
		h.charset = "utf-8"
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
		h.Next.ServeHTTP(rw, req)
		return
	}

	fullname := filepath.Join(h.Config.StaticRoot, req.URL.Path)

	fi, err := os.Stat(fullname)
	if err != nil {
		http.Error(rw, "404 not found", http.StatusNotFound)
		return
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

		n, err := io.Copy(rw, file)

		log.Info().Context(ri.LogContext).Int("http_status", http.StatusOK).Int64("http_content_length", n).Msg("static_root request")

		return
	}

	infos, err := ioutil.ReadDir(fullname)
	if err != nil {
		http.Error(rw, "500 internal server error", http.StatusInternalServerError)
		return
	}

	var b bytes.Buffer
	err = h.template.Execute(&b, struct {
		Request   *http.Request
		FileInfos []os.FileInfo
	}{req, infos})
	if err != nil {
		http.Error(rw, "500 internal server error", http.StatusInternalServerError)
		return
	}

	if addFile := h.Config.StaticAddAfterBody; addFile != "" {
		if data, err := ioutil.ReadFile(filepath.Join(h.Config.StaticRoot, addFile)); err == nil {
			b.Write(data)
		}
	}

	rw.Header().Set("content-type", "text/html;charset="+h.charset)
	rw.Write(b.Bytes())
	return
}
