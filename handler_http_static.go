package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/phuslu/log"
	"github.com/tg123/go-htpasswd"
)

const defaultStaticBody = `<html>
<head><title>Index of {{.Request.URL.Path}}</title></head>
<body>
<h1>Index of {{.Request.URL.Path}}</h1><hr><pre><a href="../">../</a>
{{range .FileInfos -}}
{{if .IsDir -}}
<a href="{{.Name}}/">{{.Name}}/</a>                                                  {{.ModTime.Format "02-Jan-2006 15:04"}}       -
{{else -}}
<a href="{{.Name}}">{{.Name}}</a>                                                  {{.ModTime.Format "02-Jan-2006 15:04"}}    {{.Size}}
{{end -}}
{{end}}</pre><hr></body>
</html>
{{tryfiles (print .StaticRoot "/autoindex.html") }}
`

type HTTPStaticHandler struct {
	Next      http.Handler
	Config    HTTPConfig
	Functions template.FuncMap

	index   string
	headers *template.Template
	body    *template.Template
}

func (h *HTTPStaticHandler) Load() (err error) {
	h.index = h.Config.StaticIndex
	if h.index == "" {
		h.index = "index.html"
	}

	h.headers, err = template.New(h.Config.StaticHeaders).Funcs(h.Functions).Parse(h.Config.StaticHeaders)
	if err != nil {
		return
	}

	body := h.Config.StaticBody
	if body == "" {
		body = defaultStaticBody
	}

	h.body, err = template.New(body).Funcs(h.Functions).Parse(body)
	if err != nil {
		return
	}

	return
}

func (h *HTTPStaticHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	if h.Config.StaticRoot == "" {
		if h.Config.StaticBody != "" {
			h.addHeaders(rw, req)
			h.body.Execute(rw, struct {
				StaticRoot string
				Request    *http.Request
				FileInfos  []os.FileInfo
			}{h.Config.StaticRoot, req, nil})
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
		// .htpasswd
		htfile := filepath.Join(fullname, ".htpasswd")
		if fi1, err := os.Stat(htfile); err == nil && !fi1.IsDir() {
			ht, err := htpasswd.New(htfile, htpasswd.DefaultSystems, nil)
			if err != nil {
				http.Error(rw, "500 internal server error", http.StatusInternalServerError)
				return
			}
			s := req.Header.Get("authorization")
			if s == "" || !strings.HasPrefix(s, "Basic ") {
				rw.Header().Set("www-authenticate", `Basic realm="Authentication Required"`)
				http.Error(rw, "401 unauthorised", http.StatusUnauthorized)
				return
			}
			data, err := base64.StdEncoding.DecodeString(s[6:])
			if err != nil {
				rw.Header().Set("www-authenticate", `Basic realm="Authentication Required"`)
				http.Error(rw, "401 unauthorised", http.StatusUnauthorized)
				return
			}
			parts := strings.SplitN(string(data), ":", 2)
			if len(parts) != 2 || !ht.Match(parts[0], parts[1]) {
				rw.Header().Set("www-authenticate", `Basic realm="Authentication Required"`)
				http.Error(rw, "401 unauthorised", http.StatusUnauthorized)
				return
			}
		}
		// index.html
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

		h.addHeaders(rw, req)
		if s := mime.TypeByExtension(filepath.Ext(fullname)); s != "" {
			rw.Header().Set("content-type", s)
		} else {
			rw.Header().Set("content-type", "application/octet-stream")
		}
		rw.Header().Set("accept-ranges", "bytes")
		if s := req.Header.Get("range"); s == "" {
			rw.Header().Set("content-length", strconv.FormatInt(fi.Size(), 10))
			rw.WriteHeader(http.StatusOK)
			n, err := io.Copy(rw, file)
			log.Info().Context(ri.LogContext).Err(err).Int("http_status", http.StatusOK).Int64("http_content_length", n).Msg("static_root request")
		} else {
			if !strings.HasPrefix(s, "bytes=") {
				http.Error(rw, "400 bad request", http.StatusBadRequest)
				return
			}
			parts := strings.SplitN(s[6:], "-", 2)
			if len(parts) != 2 {
				http.Error(rw, "400 bad request", http.StatusBadRequest)
				return
			}
			// calc ranges
			var filesize = fi.Size()
			var ranges [2]int64
			switch {
			case parts[0] == "":
				ranges[0] = 0
			case parts[1] == "":
				if filesize == 0 {
					ranges[1] = 0
				} else {
					ranges[1] = filesize - 1
				}
			default:
				for i, part := range parts {
					ranges[i], err = strconv.ParseInt(part, 10, 64)
					if err != nil {
						http.Error(rw, "400 bad request", http.StatusBadRequest)
						return
					}
				}
			}
			// content-length
			length := ranges[1] - ranges[0] + 1
			if length <= 0 {
				http.Error(rw, "400 bad request", http.StatusBadRequest)
				return
			}
			// limit reader
			if ranges[0] > 0 {
				file.Seek(ranges[0], 0)
			}
			var fr io.Reader = file
			if ranges[1] < filesize-1 {
				fr = io.LimitReader(file, length)
			}
			// send data
			rw.Header().Set("content-range", fmt.Sprintf("bytes %d-%d/%d", ranges[0], ranges[1], filesize))
			rw.Header().Set("content-length", strconv.FormatInt(length, 10))
			rw.WriteHeader(http.StatusPartialContent)
			n, err := io.Copy(rw, fr)
			log.Info().Context(ri.LogContext).Err(err).Int("http_status", http.StatusOK).Int64("http_content_length", n).Msg("static_root request")
		}

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
	err = h.body.Execute(&b, struct {
		StaticRoot string
		Request    *http.Request
		FileInfos  []os.FileInfo
	}{h.Config.StaticRoot, req, infos2})
	if err != nil {
		http.Error(rw, "500 internal server error", http.StatusInternalServerError)
		return
	}

	h.addHeaders(rw, req)
	rw.Header().Set("content-type", "text/html;charset=utf-8")
	rw.Write(b.Bytes())
	return
}

func (h *HTTPStaticHandler) addHeaders(rw http.ResponseWriter, req *http.Request) {
	var sb strings.Builder
	h.headers.Execute(&sb, struct {
		StaticRoot string
		Request    *http.Request
		FileInfos  []os.FileInfo
	}{h.Config.StaticRoot, req, nil})

	for _, line := range strings.Split(sb.String(), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			rw.Header().Add(parts[0], strings.TrimSpace(parts[1]))
		}
	}
}
