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
	"strconv"
	"strings"
	"text/template"

	"github.com/phuslu/log"
	"golang.org/x/net/webdav"
)

type HTTPWebIndexHandler struct {
	Root       string
	Headers    string
	Body       string
	Functions  template.FuncMap
	DavEnabled bool
	DavPrefixs []string

	headers *template.Template
	body    *template.Template
	dav     *webdav.Handler
}

//go:embed autoindex.tmpl
var autoindexTemplate []byte

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

	if h.DavEnabled {
		h.dav = &webdav.Handler{
			FileSystem: webdav.Dir(h.Root),
			LockSystem: webdav.NewMemLS(),
		}
	}

	return
}

func (h *HTTPWebIndexHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	log.Debug().Context(ri.LogContext).Interface("headers", req.Header).Msg("web index request")

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

	if h.DavEnabled {
		if req.Method == http.MethodOptions {
			h.dav.ServeHTTP(rw, req)

			return
		}

		prefix := ""
		for _, s := range h.DavPrefixs {
			if strings.HasPrefix(req.URL.Path, s) {
				prefix = s
				break
			}
		}
		if prefix != "" {
			log.Info().Context(ri.LogContext).Interface("headers", req.Header).Msg("web dav request")

			davfile := filepath.Join(h.Root, prefix+"/.davpasswd")
			if err := HtpasswdVerify(davfile, req); err != nil && !os.IsNotExist(err) {
				log.Error().Context(ri.LogContext).Err(err).Msg("web dav auth error")
				rw.Header().Set("www-authenticate", `Basic realm="Authentication Required"`)
				http.Error(rw, "401 unauthorised: "+err.Error(), http.StatusUnauthorized)

				return
			}

			// fixup path/raw_path for dav handler
			// req.URL.Path = req.URL.Path[len(h.Root):]
			// req.URL.RawPath = req.URL.RawPath[len(h.Root):]
			h.dav.ServeHTTP(rw, req)

			return
		}
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
		WebRoot   string
		Request   *http.Request
		FileInfos []fs.FileInfo
	}{h.Root, req, infos})
	if err != nil {
		http.Error(rw, "500 internal server error", http.StatusInternalServerError)
		return
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
