package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/phuslu/log"
)

type HTTPHandler interface {
	http.Handler
	Load() error
}

type HTTPMainHandler struct {
	Config          HTTPConfig
	TLSConfigurator *TLSConfigurator
	ServerNames     StringSet
	ForwardHandler  HTTPHandler
	WebHandler      HTTPHandler
}

type RequestInfo struct {
	RemoteIP        string
	ServerAddr      string
	ServerName      string
	TLSVersion      TLSVersion
	ClientHelloInfo *tls.ClientHelloInfo
	TraceID         log.XID
	LogContext      log.Context
}

var RequestInfoContextKey = struct {
	name string
}{"request-info"}

var riPool = sync.Pool{
	New: func() interface{} {
		return new(RequestInfo)
	},
}

//go:embed mime.types
var mimeTypes []byte

func (h *HTTPMainHandler) Load() error {
	scanner := bufio.NewScanner(bytes.NewReader(mimeTypes))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) != 2 {
			continue
		}
		mime.AddExtensionType("."+parts[1], parts[0])
	}

	for key, value := range h.Config.Mimes {
		mime.AddExtensionType(strings.ToLower("."+strings.Trim(key, ".")), value)
	}

	return nil
}

func (h *HTTPMainHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := riPool.Get().(*RequestInfo)
	defer riPool.Put(ri)

	ri.RemoteIP, _, _ = net.SplitHostPort(req.RemoteAddr)
	ri.ServerAddr = req.Context().Value(http.LocalAddrContextKey).(net.Addr).String()
	if req.TLS != nil {
		ri.ServerName = req.TLS.ServerName
		ri.TLSVersion = TLSVersion(req.TLS.Version)
	} else {
		ri.ServerName = ""
		ri.TLSVersion = 0
	}

	ri.ClientHelloInfo = nil
	if h.TLSConfigurator != nil {
		if v, ok := h.TLSConfigurator.ClientHelloCache.Load(req.RemoteAddr); ok {
			ri.ClientHelloInfo = v.(*tls.ClientHelloInfo)
		}
	}
	ri.TraceID = log.NewXID()

	ri.LogContext = log.NewContext(ri.LogContext[:0]).
		Xid("trace_id", ri.TraceID).
		Str("server_name", ri.ServerName).
		Str("server_addr", ri.ServerAddr).
		Str("tls_version", ri.TLSVersion.String()).
		Str("remote_ip", ri.RemoteIP).
		Str("user_agent", req.UserAgent()).
		Str("http_method", req.Method).
		Str("http_proto", req.Proto).
		Str("http_host", req.Host).
		Str("http_url", req.URL.String()).
		Value()

	req = req.WithContext(context.WithValue(req.Context(), RequestInfoContextKey, ri))
	if req.Method == http.MethodConnect || !h.ServerNames.Contains(req.Host) {
		h.ForwardHandler.ServeHTTP(rw, req)
	} else {
		h.WebHandler.ServeHTTP(rw, req)
	}
}
