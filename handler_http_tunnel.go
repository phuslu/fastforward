package main

import (
	"net/http"

	"github.com/phuslu/log"
)

type HTTPTunnelHandler struct {
	Config       HTTPConfig
	TunnelLogger log.Logger
}

func (h *HTTPTunnelHandler) Load() error {
	return nil
}

func (h *HTTPTunnelHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)
	h.TunnelLogger.Info().Xid("trace_id", ri.TraceID).Str("server_name", ri.ServerName).Str("server_addr", ri.ServerAddr).Str("tls_version", ri.TLSVersion.String()).Str("remote_ip", ri.RemoteIP).Str("http_method", req.Method).Str("http_host", req.Host).Str("http_proto", req.Proto).Str("user_agent", req.UserAgent()).Msg("tunnel log")

}
