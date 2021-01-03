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

type HTTPWebPacHandler struct {
	Config    HTTPConfig
	Functions template.FuncMap
}

func (h *HTTPWebPacHandler) Load() error {
	return nil
}

func (h *HTTPWebPacHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	if req.TLS != nil && !(req.ProtoAtLeast(2, 0) && ri.TLSVersion == tls.VersionTLS13 && IsTLSGreaseCode(ri.ClientHelloInfo.CipherSuites[0])) {
		http.NotFound(rw, req)
		return
	}

	if !h.Config.Pac.Enabled || !strings.HasSuffix(req.URL.Path, ".pac") {
		http.NotFound(rw, req)
		return
	}

	log.Info().Context(ri.LogContext).Msg("pac request")

	data, err := ioutil.ReadFile(req.URL.Path[1:])
	if err != nil {
		log.Error().Context(ri.LogContext).Err(err).Msg("read pac error")
		http.NotFound(rw, req)
		return
	}

	var updateAt time.Time
	if fi, err := os.Stat(req.URL.Path[1:]); err == nil {
		updateAt = fi.ModTime()
	}

	tmpl, err := template.New(req.URL.Path[1:]).Funcs(h.Functions).Parse(string(data))
	if err != nil {
		log.Error().Context(ri.LogContext).Err(err).Msg("parse pac error")
		http.NotFound(rw, req)
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
		UpdatedAt: updateAt,
		Scheme:    proxyScheme,
		Host:      proxyHost,
	})
	if err != nil {
		log.Error().Context(ri.LogContext).Err(err).Msg("eval pac error")
		http.NotFound(rw, req)
		return
	}

	supportGzip := strings.Contains(req.Header.Get("accept-encoding"), "gzip")

	pac := b.Bytes()
	if supportGzip {
		b := new(bytes.Buffer)
		w := gzip.NewWriter(b)
		w.Write(pac)
		w.Close()
		pac = b.Bytes()
	}

	rw.Header().Add("cache-control", "max-age=86400")
	rw.Header().Add("content-type", "text/plain; charset=UTF-8")
	rw.Header().Add("content-length", strconv.FormatUint(uint64(len(pac)), 10))
	if supportGzip {
		rw.Header().Add("content-encoding", "gzip")
	}
	rw.WriteHeader(http.StatusOK)
	rw.Write(pac)
}
