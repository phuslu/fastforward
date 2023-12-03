package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/phuslu/log"
)

type TunnelHandler struct {
	Config         TunnelConfig
	ForwardLogger  log.Logger
	RegionResolver *RegionResolver
	LocalDialer    Dialer

	tunnel atomic.Value // yamux.Session
}

func (h *TunnelHandler) Load() error {
	return nil
}

func (h *TunnelHandler) ServeConn(conn net.Conn) {

	v := h.tunnel.Load()
	if v == nil {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		br := bufio.NewReader(conn)

		req, err := http.ReadRequest(br)
		if err != nil {
			log.Error().Err(err).Msg("tunnel read conn error")
			conn.Close()
			return
		}
		if req.Header.Get("x-tunnel-key") != h.Config.Server.Key {
			log.Error().Err(err).Msg("tunnel verfiy conn key error")
			conn.Close()
			return
		}

		fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")

		if n := br.Buffered(); n > 0 {
			data, _ := br.Peek(n)
			conn = &ConnWithData{conn, data}
		}

		session, err := yamux.Client(conn, nil)
		if err != nil {
			log.Error().Err(err).Msg("tunnel create session error")
			conn.Close()
			return
		}

		h.tunnel.Store(session)

		return
	}

	session := v.(*yamux.Session)

	stream, err := session.Open()
	if err != nil {
		log.Error().Err(err).Msg("tunnel open stream error")
		time.Sleep(10 * time.Millisecond)
		conn.Close()
		return
	}

	go func(stream, conn net.Conn) {
		defer stream.Close()
		defer conn.Close()
		go io.Copy(stream, conn)
		_, err := io.Copy(conn, stream)
		if err != nil {
			log.Error().Err(err).Msg("forward tunnel error")
		}
	}(stream, conn)

	return
}

func (h *TunnelHandler) Client(ctx context.Context) {
	connect := func() (*yamux.Session, error) {
		conn, err := h.LocalDialer.DialContext(ctx, "tcp", h.Config.Client.RemoteAddr)
		if err != nil {
			return nil, err
		}

		_, err = io.WriteString(conn, strings.Join([]string{
			"GET / HTTP/1.1",
			"x-tunnel-key: " + h.Config.Client.Key,
		}, "\r\n")+"\r\n\r\n")
		if err != nil {
			return nil, err
		}

		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			log.Error().Err(err).Msg("tunnel read conn response error")
			conn.Close()
			return nil, err
		}
		if resp.StatusCode != http.StatusSwitchingProtocols {
			log.Error().Int("resp_status_code", resp.StatusCode).Msg("tunnel read conn response error")
			conn.Close()
			return nil, fmt.Errorf("tunnel error: read conn response %d", resp.StatusCode)
		}

		if n := br.Buffered(); n > 0 {
			data, _ := br.Peek(n)
			conn = &ConnWithData{conn, data}
		}

		session, err := yamux.Server(conn, nil)
		if err != nil {
			return nil, err
		}

		return session, nil
	}

	for {
		session, err := connect()
		if err != nil {
			log.Error().Err(err).Msg("tunnel error: create yamux session")
			time.Sleep(2000 * time.Millisecond)
			continue
		}
		log.Info().Msg("tunnel new session")

		for {
			stream, err := session.Accept()
			if err != nil {
				log.Error().Err(err).Msg("tunnel error: accept yamux stream")
				time.Sleep(100 * time.Millisecond)
				session.Close()
				break
			}

			log.Info().Msg("tunnel new session")

			go func(ctx context.Context, stream net.Conn) {
				defer stream.Close()

				conn, err := h.LocalDialer.DialContext(ctx, "tcp", h.Config.Client.LocalAddr)
				if err != nil {
					log.Error().Err(err).Str("local_addr", h.Config.Client.LocalAddr).Msg("tunnel error: failed to connect local addr")
					return
				}
				defer conn.Close()

				log.Info().Msg("tunnel forward")

				go io.Copy(stream, conn)
				io.Copy(conn, stream)
			}(ctx, stream)
		}
	}
}
