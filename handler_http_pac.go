package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/phuslu/log"
)

type HTTPPacHandler struct {
	Next   http.Handler
	Config HTTPConfig

	Functions template.FuncMap
}

func (h *HTTPPacHandler) Load() error {
	if !h.Config.PacEnabled {
		return nil
	}

	return nil
}

func (h *HTTPPacHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	if req.TLS != nil && !(req.ProtoAtLeast(2, 0) && ri.TLSVersion == tls.VersionTLS13 && IsTLSGreaseCode(ri.ClientHelloInfo.CipherSuites[0])) {
		h.Next.ServeHTTP(rw, req)
		return
	}

	if !h.Config.PacEnabled || !strings.HasSuffix(req.URL.Path, ".pac") {
		h.Next.ServeHTTP(rw, req)
		return
	}

	hasGzip := strings.Contains(req.Header.Get("accept-encoding"), "gzip")

	log.Info().Context(ri.LogContext).Msg("pac request")

	data, err := ioutil.ReadFile(req.URL.Path[1:])
	if err != nil {
		log.Error().Context(ri.LogContext).Err(err).Msg("read pac error, fallback to next handler")
		h.Next.ServeHTTP(rw, req)
		return
	}

	var modTime time.Time
	if fi, err := os.Stat(req.URL.Path[1:]); err == nil {
		modTime = fi.ModTime()
	}

	tmpl, err := template.New(req.URL.Path[1:]).Funcs(h.Functions).Parse(string(data))
	if err != nil {
		log.Error().Context(ri.LogContext).Err(err).Msg("parse pac error, fallback to next handler")
		h.Next.ServeHTTP(rw, req)
		return
	}

	var proxyScheme, proxyHost, proxyPort string

	if req.TLS != nil {
		proxyScheme = "HTTPS"
		proxyPort = "443"
	} else {
		proxyScheme = "PROXY"
		proxyPort = "80"
	}

	if _, _, err := net.SplitHostPort(req.Host); err == nil {
		proxyHost = req.Host
	} else {
		proxyHost = req.Host + ":" + proxyPort
	}

	var b bytes.Buffer
	err = tmpl.Execute(&b, struct {
		Version   string
		UpdatedAt time.Time
		Scheme    string
		Host      string
	}{
		Version:   version,
		UpdatedAt: modTime,
		Scheme:    proxyScheme,
		Host:      proxyHost,
	})
	if err != nil {
		log.Error().Context(ri.LogContext).Err(err).Msg("eval pac error, fallback to next handler")
		h.Next.ServeHTTP(rw, req)
		return
	}

	pac := b.Bytes()
	if hasGzip {
		b := new(bytes.Buffer)
		w := gzip.NewWriter(b)
		w.Write(pac)
		w.Close()
		pac = b.Bytes()
	}

	rw.Header().Add("cache-control", "max-age=86400")
	rw.Header().Add("content-type", "text/plain; charset=UTF-8")
	rw.Header().Add("content-length", strconv.FormatUint(uint64(len(pac)), 10))
	if hasGzip {
		rw.Header().Add("content-encoding", "gzip")
	}
	rw.WriteHeader(http.StatusOK)
	rw.Write(pac)
}
