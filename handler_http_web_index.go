package main

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
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

//go:embed autoindex.tmpl
var autoindexTemplate []byte

type HTTPWebIndexHandler struct {
	Root         string
	Headers      string
	Body         string
	AddAfterBody string
	Functions    template.FuncMap

	headers *template.Template
	body    *template.Template
}

func (h *HTTPWebIndexHandler) Load() (err error) {
	if h.Body == "" {
		h.Body = string(autoindexTemplate)
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

	if h.Root == "" && h.Body == "" {
		http.NotFound(rw, req)
		return
	}

	if h.Root == "" {
		h.addHeaders(rw, req)
		h.body.Execute(rw, struct {
			WebRoot   string
			Request   *http.Request
			FileInfos []fs.FileInfo
		}{h.Root, req, nil})
		return
	}

	fullname := filepath.Join(h.Root, req.URL.Path)

	fi, err := os.Stat(fullname)
	if err != nil {
		http.NotFound(rw, req)
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
			n, err := io.Copy(rw, fr)
			log.Info().Context(ri.LogContext).Err(err).Int("http_status", http.StatusOK).Int64("http_content_length", n).Msg("web_root request")
		}

		return
	}

	infos, err := ioutil.ReadDir(fullname)
	if err != nil {
		http.Error(rw, "500 internal server error", http.StatusInternalServerError)
		return
	}

	infos2 := make([]fs.FileInfo, 0, len(infos))
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
		WebRoot   string
		Request   *http.Request
		FileInfos []fs.FileInfo
	}{h.Root, req, infos2})
	if err != nil {
		http.Error(rw, "500 internal server error", http.StatusInternalServerError)
		return
	}
	if h.AddAfterBody != "" {
		filename := filepath.Join(h.Root, h.AddAfterBody)
		if data, err := ioutil.ReadFile(filename); err == nil {
			b.Write(data)
		}
	}

	h.addHeaders(rw, req)
	rw.Header().Set("content-type", "text/html;charset=utf-8")
	rw.Write(b.Bytes())
}

func (h *HTTPWebIndexHandler) addHeaders(rw http.ResponseWriter, req *http.Request) {
	var sb strings.Builder
	h.headers.Execute(&sb, struct {
		WebRoot   string
		Request   *http.Request
		FileInfos []fs.FileInfo
	}{h.Root, req, nil})
	for _, line := range strings.Split(sb.String(), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			rw.Header().Add(parts[0], strings.TrimSpace(parts[1]))
		}
	}
}
