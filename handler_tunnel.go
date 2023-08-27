package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/phuslu/log"
)

type TunnelRequest struct {
	RemoteAddr string
	RemoteIP   string
	ServerAddr string
	TraceID    log.XID
}

type TunnelHandler struct {
	Config         TunnelConfig
	ForwardLogger  log.Logger
	RegionResolver *RegionResolver
	LocalTransport *http.Transport
	LocalDialer    Dialer
}

func (h *TunnelHandler) Load() error {
	h.LocalTransport = h.LocalTransport.Clone()

	h.LocalTransport.ForceAttemptHTTP2 = false

	if h.LocalTransport.TLSClientConfig != nil {
		h.LocalTransport.TLSClientConfig.NextProtos = []string{"http/1.1"}
	}

	return nil
}

func (h *TunnelHandler) Serve(ctx context.Context) {
	api := fmt.Sprintf(h.Config.APIFormat, h.Config.RemoteAddr)
	req0, _ := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)

	resp, err := h.LocalTransport.RoundTrip(req0)
	if err != nil {
		log.Error().Err(err).Str("tunnel_api", api).Msg("tunnel error: failed to connect remote api")
		return
	}

	rwc, ok := resp.Body.(io.ReadWriteCloser)
	if !ok {
		log.Error().Str("tunnel_api", api).Int("status_code", resp.StatusCode).Msg("tunnel error: 101 switching protocols response with non-writable body")
		return
	}
	defer rwc.Close()

	session, err := yamux.Server(rwc, nil)
	if err != nil {
		log.Error().Err(err).Msg("tunnel error: create yamux session")
		return
	}
	defer session.Close()

	for {
		stream, err := session.Accept()
		if err != nil {
			log.Error().Err(err).Msg("tunnel error: accept yamux stream")
			time.Sleep(10 * time.Millisecond)
			continue
		}
		go func(ctx context.Context, stream net.Conn) {
			defer stream.Close()
			conn, err := h.LocalDialer.DialContext(ctx, "tcp", h.Config.LocalAddr)
			if !ok {
				log.Error().Err(err).Str("local_addr", h.Config.LocalAddr).Msg("tunnel error: failed to connect local addr")
				return
			}
			defer conn.Close()

			req := TunnelRequest{
				RemoteAddr: "",
				RemoteIP:   "",
				ServerAddr: "",
				TraceID:    log.NewXID(),
			}

			if h.Config.Log {
				var country, region, city string
				if h.RegionResolver.MaxmindReader != nil {
					country, region, city, _ = h.RegionResolver.LookupCity(ctx, net.ParseIP(req.RemoteIP))
				}
				h.ForwardLogger.Info().Str("remote_ip", req.RemoteIP).Str("remote_country", country).Str("remote_region", region).Str("remote_city", city).Msg("forward port request end")
			}

			go io.Copy(stream, conn)
			io.Copy(conn, stream)
		}(ctx, stream)
	}

	return
}
