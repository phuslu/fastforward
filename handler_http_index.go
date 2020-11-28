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

const defaultIndexBody = `<html>
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
{{tryfiles (print .IndexRoot "/.autoindex.html") }}
`

type HTTPIndexHandler struct {
	Next      http.Handler
	Config    HTTPConfig
	Functions template.FuncMap

	headers *template.Template
	body    *template.Template
}

func (h *HTTPIndexHandler) Load() (err error) {
	for key, value := range defaultTypesMap {
		mime.AddExtensionType(key, value)
	}
	for key, value := range h.Config.Index.Mimes {
		mime.AddExtensionType(strings.ToLower("."+strings.Trim(key, ".")), value)
	}

	h.headers, err = template.New(h.Config.Index.Headers).Funcs(h.Functions).Parse(h.Config.Index.Headers)
	if err != nil {
		return
	}

	body := h.Config.Index.Body
	if body == "" {
		body = defaultIndexBody
	}

	h.body, err = template.New(body).Funcs(h.Functions).Parse(body)
	if err != nil {
		return
	}

	return
}

func (h *HTTPIndexHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	if h.Config.Index.Root == "" && h.Config.Index.Body == "" {
		h.Next.ServeHTTP(rw, req)
		return
	}

	if h.Config.Index.Root == "" {
		h.addHeaders(rw, req)
		h.body.Execute(rw, struct {
			IndexRoot string
			Request   *http.Request
			FileInfos []os.FileInfo
		}{h.Config.Index.Root, req, nil})
		return
	}

	fullname := filepath.Join(h.Config.Index.Root, req.URL.Path)

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
			log.Info().Context(ri.LogContext).Err(err).Int("http_status", http.StatusOK).Int64("http_content_length", n).Msg("index_root request")
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
			log.Info().Context(ri.LogContext).Err(err).Int("http_status", http.StatusOK).Int64("http_content_length", n).Msg("index_root request")
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
		IndexRoot string
		Request   *http.Request
		FileInfos []os.FileInfo
	}{h.Config.Index.Root, req, infos2})
	if err != nil {
		http.Error(rw, "500 internal server error", http.StatusInternalServerError)
		return
	}

	h.addHeaders(rw, req)
	rw.Header().Set("content-type", "text/html;charset=utf-8")
	rw.Write(b.Bytes())
	return
}

func (h *HTTPIndexHandler) addHeaders(rw http.ResponseWriter, req *http.Request) {
	if h.Config.Index.Headers == "" {
		return
	}

	var sb strings.Builder
	h.headers.Execute(&sb, struct {
		IndexRoot string
		Request   *http.Request
		FileInfos []os.FileInfo
	}{h.Config.Index.Root, req, nil})

	for _, line := range strings.Split(sb.String(), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) == 2 {
			rw.Header().Add(parts[0], strings.TrimSpace(parts[1]))
		}
	}
}

// see https://github.com/python/cpython/blob/master/Lib/mimetypes.py#L414
var defaultTypesMap = map[string]string{
	".a":           "application/octet-stream",
	".ai":          "application/postscript",
	".aif":         "audio/x-aiff",
	".aifc":        "audio/x-aiff",
	".aiff":        "audio/x-aiff",
	".au":          "audio/basic",
	".avi":         "video/x-msvideo",
	".bat":         "text/plain",
	".bcpio":       "application/x-bcpio",
	".bin":         "application/octet-stream",
	".bmp":         "image/bmp",
	".c":           "text/plain",
	".cdf":         "application/x-netcdf",
	".cpio":        "application/x-cpio",
	".csh":         "application/x-csh",
	".css":         "text/css",
	".csv":         "text/csv",
	".dll":         "application/octet-stream",
	".doc":         "application/msword",
	".dot":         "application/msword",
	".dvi":         "application/x-dvi",
	".eml":         "message/rfc822",
	".eps":         "application/postscript",
	".etx":         "text/x-setext",
	".exe":         "application/octet-stream",
	".gif":         "image/gif",
	".gtar":        "application/x-gtar",
	".h":           "text/plain",
	".h5":          "application/x-hdf5",
	".hdf":         "application/x-hdf",
	".htm":         "text/html",
	".html":        "text/html",
	".ico":         "image/vnd.microsoft.icon",
	".ief":         "image/ief",
	".jpe":         "image/jpeg",
	".jpeg":        "image/jpeg",
	".jpg":         "image/jpeg",
	".js":          "application/javascript",
	".json":        "application/json",
	".ksh":         "text/plain",
	".latex":       "application/x-latex",
	".m1v":         "video/mpeg",
	".m3u":         "application/vnd.apple.mpegurl",
	".m3u8":        "application/vnd.apple.mpegurl",
	".man":         "application/x-troff-man",
	".me":          "application/x-troff-me",
	".mht":         "message/rfc822",
	".mhtml":       "message/rfc822",
	".mif":         "application/x-mif",
	".mjs":         "application/javascript",
	".mov":         "video/quicktime",
	".movie":       "video/x-sgi-movie",
	".mp2":         "audio/mpeg",
	".mp3":         "audio/mpeg",
	".mp4":         "video/mp4",
	".mpa":         "video/mpeg",
	".mpe":         "video/mpeg",
	".mpeg":        "video/mpeg",
	".mpg":         "video/mpeg",
	".ms":          "application/x-troff-ms",
	".nc":          "application/x-netcdf",
	".nws":         "message/rfc822",
	".o":           "application/octet-stream",
	".obj":         "application/octet-stream",
	".oda":         "application/oda",
	".p12":         "application/x-pkcs12",
	".p7c":         "application/pkcs7-mime",
	".pbm":         "image/x-portable-bitmap",
	".pdf":         "application/pdf",
	".pfx":         "application/x-pkcs12",
	".pgm":         "image/x-portable-graymap",
	".pl":          "text/plain",
	".png":         "image/png",
	".pnm":         "image/x-portable-anymap",
	".pot":         "application/vnd.ms-powerpoint",
	".ppa":         "application/vnd.ms-powerpoint",
	".ppm":         "image/x-portable-pixmap",
	".pps":         "application/vnd.ms-powerpoint",
	".ppt":         "application/vnd.ms-powerpoint",
	".ps":          "application/postscript",
	".pwz":         "application/vnd.ms-powerpoint",
	".py":          "text/x-python",
	".pyc":         "application/x-python-code",
	".pyo":         "application/x-python-code",
	".qt":          "video/quicktime",
	".ra":          "audio/x-pn-realaudio",
	".ram":         "application/x-pn-realaudio",
	".ras":         "image/x-cmu-raster",
	".rdf":         "application/xml",
	".rgb":         "image/x-rgb",
	".roff":        "application/x-troff",
	".rtx":         "text/richtext",
	".sgm":         "text/x-sgml",
	".sgml":        "text/x-sgml",
	".sh":          "application/x-sh",
	".shar":        "application/x-shar",
	".snd":         "audio/basic",
	".so":          "application/octet-stream",
	".src":         "application/x-wais-source",
	".sv4cpio":     "application/x-sv4cpio",
	".sv4crc":      "application/x-sv4crc",
	".svg":         "image/svg+xml",
	".swf":         "application/x-shockwave-flash",
	".t":           "application/x-troff",
	".tar":         "application/x-tar",
	".tcl":         "application/x-tcl",
	".tex":         "application/x-tex",
	".texi":        "application/x-texinfo",
	".texinfo":     "application/x-texinfo",
	".tif":         "image/tiff",
	".tiff":        "image/tiff",
	".tr":          "application/x-troff",
	".tsv":         "text/tab-separated-values",
	".txt":         "text/plain",
	".ustar":       "application/x-ustar",
	".vcf":         "text/x-vcard",
	".wasm":        "application/wasm",
	".wav":         "audio/x-wav",
	".webm":        "video/webm",
	".webmanifest": "application/manifest+json",
	".wiz":         "application/msword",
	".wsdl":        "application/xml",
	".xbm":         "image/x-xbitmap",
	".xlb":         "application/vnd.ms-excel",
	".xls":         "application/vnd.ms-excel",
	".xml":         "text/xml",
	".xpdl":        "application/xml",
	".xpm":         "image/x-xpixmap",
	".xsl":         "application/xml",
	".xwd":         "image/x-xwindowdump",
	".zip":         "application/zip",
}
