package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/phuslu/log"
)

type StreamRequest struct {
	RemoteAddr string
	RemoteIP   string
	ServerAddr string
	TraceID    log.XID
}

type StreamHandler struct {
	Config         StreamConfig
	ForwardLogger  log.Logger
	RegionResolver *RegionResolver
	LocalDialer    *LocalDialer
	Dialers        map[string]Dialer

	tlsConfig *tls.Config
}

func (h *StreamHandler) Load() error {
	keyfile, certfile := h.Config.Keyfile, h.Config.Certfile
	if certfile == "" {
		certfile = keyfile
	}

	if keyfile == "" {
		return nil
	}

	cert, err := tls.LoadX509KeyPair(certfile, keyfile)
	if err != nil {
		return err
	}

	h.tlsConfig = &tls.Config{
		MaxVersion:               tls.VersionTLS13,
		MinVersion:               tls.VersionTLS10,
		Certificates:             []tls.Certificate{cert},
		PreferServerCipherSuites: true,
	}

	return nil
}

func (h *StreamHandler) ServeConn(conn net.Conn) {
	ctx := context.Background()

	defer conn.Close()

	var req StreamRequest
	req.RemoteAddr = conn.RemoteAddr().String()
	req.RemoteIP, _, _ = net.SplitHostPort(req.RemoteAddr)
	req.ServerAddr = conn.LocalAddr().String()
	req.TraceID = log.NewXID()

	if h.tlsConfig != nil {
		tconn := tls.Server(conn, h.tlsConfig)
		err := tconn.HandshakeContext(ctx)
		if err != nil {
			log.Error().Err(err).Str("stream_proxy_pass", h.Config.ProxyPass).Str("remote_ip", req.RemoteIP).Str("stream_dialer_name", h.Config.Dialer).Msg("connect remote host failed")
			return
		}
		conn = tconn
	}

	dail := h.LocalDialer.DialContext
	if h.Config.Dialer != "" {
		dialer, ok := h.Dialers[h.Config.Dialer]
		if !ok {
			log.Error().Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("stream_dialer_name", h.Config.Dialer).Msg("dialer not exists")
			return
		}
		dail = dialer.DialContext
	}

	rconn, err := func(ctx context.Context) (net.Conn, error) {
		if h.Config.DialTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(h.Config.DialTimeout)*time.Second)
			defer cancel()
		}
		if !strings.Contains(h.Config.ProxyPass, "://") {
			return dail(ctx, "tcp", h.Config.ProxyPass)
		}
		u, err := url.Parse(h.Config.ProxyPass)
		if err != nil {
			return nil, err
		}
		switch u.Scheme {
		case "unix", "unixgram":
			return dail(ctx, u.Scheme, u.Path)
		default:
			return dail(ctx, u.Scheme, u.Host)
		}
	}(ctx)
	if err != nil {
		log.Error().Err(err).Str("stream_proxy_pass", h.Config.ProxyPass).Str("remote_ip", req.RemoteIP).Str("stream_dialer_name", h.Config.Dialer).Msg("connect remote host failed")
		return
	}
	defer rconn.Close()

	go io.Copy(rconn, conn)
	_, err = io.Copy(conn, NewRateLimitReader(rconn, h.Config.SpeedLimit))

	if h.Config.Log {
		var country, region, city string
		if h.RegionResolver.MaxmindReader != nil {
			country, region, city, _ = h.RegionResolver.LookupCity(ctx, net.ParseIP(req.RemoteIP))
		}
		h.ForwardLogger.Info().Stringer("trace_id", req.TraceID).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("remote_country", country).Str("remote_region", region).Str("remote_city", city).Str("stream_dialer_name", h.Config.Dialer).Msg("forward port request end")
	}

	return
}
