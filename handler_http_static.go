package main

import (
	"bytes"
	"html/template"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const defaultStaticTemplate = `
<html>
<head><title>Index of {{.Request.URL.Path}}</title></head>
<body>
<h1>Index of {{.Request.URL.Path}}</h1><hr><pre><a href="../">../</a>
{{range .FileInfos}}
<a href="{{.Name}}">{{.Name}}</a>    {{.ModTime}}    {{.Size}}
{{end}}</pre><hr></body>
</html>
`

type HTTPStaticHandler struct {
	Next      http.Handler
	Config    HTTPConfig
	Functions template.FuncMap

	Template *template.Template
}

func (h *HTTPStaticHandler) Load() error {
	s := h.Config.StaticTemplate
	if s == "" {
		s = defaultStaticTemplate
	}

	tmpl, err := template.New(s).Funcs(h.Functions).Parse(s)
	if err != nil {
		return err
	}

	h.Template = tmpl

	return nil
}

func (h *HTTPStaticHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

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

		io.Copy(rw, file)
		return
	}

	if !strings.HasSuffix(fullname, "/") {
		req.URL.Path += "/"
		http.Redirect(rw, req, req.URL.String(), http.StatusFound)
		return
	}

	infos, err := ioutil.ReadDir(fullname)
	if err != nil {
		http.Error(rw, "500 internal server error", http.StatusInternalServerError)
		return
	}

	var b bytes.Buffer
	err = h.Template.Execute(&b, struct {
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

	rw.Write(b.Bytes())
	return
}
