package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"github.com/mileusna/useragent"
	"github.com/phuslu/log"
)

type HTTPWebIndexHandler struct {
	Location  string
	Root      string
	Headers   string
	Body      string
	File      string
	Functions template.FuncMap

	headers *template.Template
	body    *template.Template
}

func (h *HTTPWebIndexHandler) Load() (err error) {
	if h.Body == "" && h.Root != "" {
		h.Body = autoindexTemplate
	}

	h.headers, err = template.New(h.Headers).Funcs(h.Functions).Parse(h.Headers)
	if err != nil {
		return
	}

	h.body, err = template.New(h.Body).Funcs(h.Functions).Parse(h.Body)
	if err != nil {
		return
	}

	return
}

func (h *HTTPWebIndexHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	log.Debug().Context(ri.LogContext).Interface("headers", req.Header).Msg("web index request")

	if h.Root == "" && h.Headers == "" && h.Body == "" && h.File == "" {
		http.NotFound(rw, req)
		return
	}

	if h.Root == "" {
		h.addHeaders(rw, req, ri)
		if s := mime.TypeByExtension(filepath.Ext(req.URL.Path)); s != "" {
			rw.Header().Set("content-type", s)
		}
		tmpl := h.body
		var fi fs.FileInfo
		if h.File != "" {
			file, err := os.Open(h.File)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			}
			defer file.Close()

			fi, err = file.Stat()
			if err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			}

			if !slices.Contains([]string{".tpl", ".html", ".pac"}, filepath.Ext(h.File)) {
				io.Copy(rw, file)
				return
			}

			data, err := io.ReadAll(file)
			if err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			}

			tmpl, err = template.New(h.File).Funcs(h.Functions).Parse(string(data))
			if err != nil {
				http.Error(rw, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		tmpl.Execute(rw, struct {
			Request    *http.Request
			UserAgent  *useragent.UserAgent
			ServerAddr string
			FileInfo   fs.FileInfo
		}{req, &ri.UserAgent, ri.ServerAddr, fi})

		return
	}

	fullname := filepath.Join(h.Root, strings.TrimPrefix(req.URL.Path, h.Location))

	fi, err := os.Stat(fullname)
	if err != nil {
		http.NotFound(rw, req)
		return
	}

	if fi.IsDir() {
		// .htpasswd
		htfile := filepath.Join(fullname, ".htpasswd")
		if err = HtpasswdVerify(htfile, req); err != nil && !os.IsNotExist(err) {
			rw.Header().Set("www-authenticate", `Basic realm="Authentication Required"`)
			http.Error(rw, "401 unauthorised: "+err.Error(), http.StatusUnauthorized)
			return
		}
		// index.html
		index := filepath.Join(fullname, "index.html")
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

		h.addHeaders(rw, req, ri)
		if s := mime.TypeByExtension(filepath.Ext(fullname)); s != "" {
			rw.Header().Set("content-type", s)
		} else {
			rw.Header().Set("content-type", "application/octet-stream")
		}
		rw.Header().Set("accept-ranges", "bytes")
		if s := req.Header.Get("range"); s == "" {
			rw.Header().Set("content-length", strconv.FormatInt(fi.Size(), 10))
			rw.WriteHeader(http.StatusOK)
			n, err := io.CopyBuffer(rw, file, make([]byte, 1<<20))
			log.Info().Context(ri.LogContext).Err(err).Int("http_status", http.StatusOK).Int64("http_content_length", n).Msg("web_root request")
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
				ranges[0], _ = strconv.ParseInt(parts[0], 10, 64)
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
			switch {
			case length < 0:
				http.Error(rw, "400 bad request", http.StatusBadRequest)
				return
			case length == 0:
				rw.WriteHeader(http.StatusNoContent)
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
			n, err := io.CopyBuffer(rw, fr, make([]byte, 1<<20))
			log.Info().Context(ri.LogContext).Err(err).Int("http_status", http.StatusOK).Int64("http_content_length", n).Msg("web_root request")
		}

		return
	}

	entries, err := os.ReadDir(fullname)
	if err != nil {
		http.Error(rw, "500 internal server error", http.StatusInternalServerError)
		return
	}

	infos := make([]fs.FileInfo, 0, len(entries))
	for i := range []int{0, 1} {
		for _, entry := range entries {
			switch {
			case entry.Name()[0] == '.':
				continue
			case i == 0 && !entry.IsDir():
				continue
			case i == 1 && entry.IsDir():
				continue
			}
			info, _ := entry.Info()
			infos = append(infos, info)
		}
	}

	var b bytes.Buffer
	err = h.body.Execute(&b, struct {
		WebRoot    string
		Request    *http.Request
		UserAgent  *useragent.UserAgent
		ServerAddr string
		FileInfos  []fs.FileInfo
	}{h.Root, req, &ri.UserAgent, ri.ServerAddr, infos})
	if err != nil {
		http.Error(rw, "500 internal server error", http.StatusInternalServerError)
		return
	}

	h.addHeaders(rw, req, ri)
	rw.Header().Set("content-type", "text/html;charset=utf-8")
	rw.Write(b.Bytes())
}

func (h *HTTPWebIndexHandler) addHeaders(rw http.ResponseWriter, req *http.Request, ri *RequestInfo) {
	var sb strings.Builder
	h.headers.Execute(&sb, struct {
		WebRoot    string
		Request    *http.Request
		UserAgent  *useragent.UserAgent
		ServerAddr string
		FileInfos  []fs.FileInfo
	}{h.Root, req, &ri.UserAgent, ri.ServerAddr, nil})

	var statusCode int
	for _, line := range strings.Split(sb.String(), "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], strings.TrimSpace(parts[1])
		if key == "status" {
			statusCode, _ = strconv.Atoi(value)
		} else {
			rw.Header().Add(key, value)
		}
	}
	if statusCode != 0 {
		rw.WriteHeader(statusCode)
	}
}

const autoindexTemplate = `
<html>
<head><title>Index of {{.Request.URL.Path}}</title></head>
<body>
<h1>Index of {{.Request.URL.Path}}</h1><hr><pre><a href="../">../</a>
{{range .FileInfos -}}
{{if .IsDir -}}
<a href="{{.Name}}/">{{.Name}}/</a>                                              {{.ModTime.Format "02-Jan-2006 15:04"}}       -
{{else -}}
<a href="{{.Name}}">{{.Name}}</a>                                              {{.ModTime.Format "02-Jan-2006 15:04"}}    {{.Size}}
{{end -}}
{{end}}</pre><hr></body>
</html>
{{ readfile "autoindex.html" }}
`
