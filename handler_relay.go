package main

import (
	"context"
	"io"
	"net"

	"github.com/phuslu/log"
)

type RelayRequest struct {
	RemoteAddr string
	RemoteIP   string
	ServerAddr string
	TraceID    log.XID
}

type RelayHandler struct {
	Config         RelayConfig
	ForwardLogger  log.Logger
	RegionResolver *RegionResolver
	LocalDialer    *LocalDialer
	Upstreams      map[string]Dialer
}

func (h *RelayHandler) Load() error {
	return nil
}

func (h *RelayHandler) ServeConn(conn net.Conn) {
	defer conn.Close()

	var req RelayRequest
	req.RemoteAddr = conn.RemoteAddr().String()
	req.RemoteIP, _, _ = net.SplitHostPort(req.RemoteAddr)
	req.ServerAddr = conn.LocalAddr().String()
	req.TraceID = log.NewXID()

	dail := h.LocalDialer.DialContext
	if h.Config.Upstream != "" {
		u, ok := h.Upstreams[h.Config.Upstream]
		if !ok {
			log.Error().Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("relay_upstream", h.Config.Upstream).Msg("upstream not exists")
			return
		}
		dail = u.DialContext
	}

	rconn, err := dail(context.Background(), "tcp", h.Config.To)
	if err != nil {
		log.Error().Err(err).Str("relay_to", h.Config.To).Str("remote_ip", req.RemoteIP).Str("relay_upstream", h.Config.Upstream).Msg("connect remote host failed")
		return
	}
	defer rconn.Close()

	go io.Copy(rconn, conn)
	_, err = io.Copy(conn, NewLimiterReader(rconn, h.Config.SpeedLimit))

	if h.Config.Log {
		var country, region, city string
		if h.RegionResolver.MaxmindReader != nil {
			country, region, city, _ = h.RegionResolver.LookupCity(context.Background(), net.ParseIP(req.RemoteIP))
		} else {
			country, _ = h.RegionResolver.LookupCountry(context.Background(), req.RemoteIP)
		}
		h.ForwardLogger.Info().Stringer("trace_id", req.TraceID).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("remote_country", country).Str("remote_region", region).Str("remote_city", city).Str("relay_upstream", h.Config.Upstream).Msg("forward port request end")
	}

	return
}
