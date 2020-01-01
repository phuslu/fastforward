package main

import (
	"context"
	"io"
	"net"
	"net/http"

	"github.com/phuslu/log"
)

type RelayRequest struct {
	RemoteAddr string
	RemoteIP   string
	ServerAddr string
}

type RelayHandler struct {
	Config         RelayConfig
	ForwardLogger  log.Logger
	RegionResolver *RegionResolver
	Dialer         *Dialer
	Upstreams      map[string]*http.Transport
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

	var dail DialFunc = h.Dialer.DialContext
	if h.Config.ForwardUpstream != "" {
		tr, ok := h.Upstreams[h.Config.ForwardUpstream]
		if !ok {
			log.Error().Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_upstream", h.Config.ForwardUpstream).Msg("upstream not exists")
			return
		}
		dail = tr.DialContext
	}

	rconn, err := dail(context.Background(), "tcp", h.Config.RelayTo)
	if err != nil {
		log.Error().Err(err).Str("relay_to", h.Config.RelayTo).Str("remote_ip", req.RemoteIP).Str("forward_upstream", h.Config.ForwardUpstream).Msg("connect remote host failed")
		return
	}
	defer rconn.Close()

	go io.Copy(rconn, conn)
	_, err = io.Copy(conn, rconn)

	if h.Config.ForwardLog {
		var country, region, city string
		if h.RegionResolver.MaxmindReader != nil {
			country, region, city, _ = h.RegionResolver.LookupCity(context.Background(), net.ParseIP(req.RemoteIP))
		} else {
			country, _ = h.RegionResolver.LookupCountry(context.Background(), req.RemoteIP)
		}
		h.ForwardLogger.Info().Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("remote_country", country).Str("remote_region", region).Str("remote_city", city).Str("forward_upstream", h.Config.ForwardUpstream).Msg("forward port request end")
	}

	return
}
