package main

import (
	"cmp"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/phuslu/log"
)

type HTTPTunnelHandler struct {
	Config       HTTPConfig
	TunnelLogger log.Logger

	csvloader *FileLoader[[]UserInfo]
}

func (h *HTTPTunnelHandler) Load() error {
	if strings.HasSuffix(h.Config.Tunnel.AuthTable, ".csv") {
		h.csvloader = &FileLoader[[]UserInfo]{
			Filename:     h.Config.Tunnel.AuthTable,
			Unmarshal:    UserCsvUnmarshal,
			PollDuration: 15 * time.Second,
			ErrorLogger:  log.DefaultLogger.Std("", 0),
		}
		records := h.csvloader.Load()
		if records == nil {
			log.Fatal().Strs("server_name", h.Config.ServerName).Str("auth_table", h.Config.Tunnel.AuthTable).Msg("load auth_table failed")
		}
		log.Info().Strs("server_name", h.Config.ServerName).Str("auth_table", h.Config.Tunnel.AuthTable).Int("auth_table_size", len(*records)).Msg("load auth_table ok")
	}

	return nil
}

func (h *HTTPTunnelHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	var user UserInfo
	if s := req.Header.Get("authorization"); s != "" {
		switch t, s, _ := strings.Cut(s, " "); t {
		case "Basic":
			if b, err := base64.StdEncoding.DecodeString(s); err == nil {
				user.Username, user.Password, _ = strings.Cut(string(b), ":")
			}
		}
	}

	if user.Username == "" || user.Password == "" {
		log.Error().Context(ri.LogContext).Str("username", user.Username).Msg("tunnel user authorization required")
		http.Error(rw, "Authorization Required", http.StatusUnauthorized)
		return
	}

	log.Info().Context(ri.LogContext).Str("username", user.Username).Str("password", user.Password).Msg("tunnel verify user")

	records := *h.csvloader.Load()
	i, ok := slices.BinarySearchFunc(records, user, func(a, b UserInfo) int { return cmp.Compare(a.Username, b.Username) })
	switch {
	case !ok:
		user.AuthError = fmt.Errorf("invalid username: %v", user.Username)
	case user.Password != records[i].Password:
		user.AuthError = fmt.Errorf("wrong password: %v", user.Username)
	default:
		user = records[i]
	}

	if user.AuthError != nil {
		log.Error().Err(user.AuthError).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel user auth failed")
		http.Error(rw, user.AuthError.Error(), http.StatusUnauthorized)
		return
	}

	if speedLimit := h.Config.Tunnel.SpeedLimit; ri.ClientTCPConn != nil && speedLimit > 0 {
		err := SetTcpMaxPacingRate(ri.ClientTCPConn, int(speedLimit))
		log.DefaultLogger.Err(err).Context(ri.LogContext).Int64("tunnel_speedlimit", speedLimit).Msg("set tunnel_speedlimit")
	}

	if allow, _ := user.Attrs["allow_tunnel"].(string); allow != "1" {
		log.Error().Context(ri.LogContext).Str("username", user.Username).Str("allow_tunnel", allow).Msg("tunnel user permission denied")
		http.Error(rw, "permission denied", http.StatusForbidden)
		return
	}

	// req.URL.Path format is /.well-known/reverse/tcp/{listen_host}/{listen_port}/
	// see https://www.ietf.org/archive/id/draft-kazuho-httpbis-reverse-tunnel-00.html
	parts := strings.Split(req.URL.Path, "/")
	addr := net.JoinHostPort(parts[len(parts)-3], parts[len(parts)-2])

	ln, err := (&net.ListenConfig{
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Interval: 15 * time.Second,
			Count:    3,
		},
	}).Listen(req.Context(), "tcp", addr)
	if err != nil {
		log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel open tcp listener error")
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Info().Context(ri.LogContext).Str("username", user.Username).Stringer("addr", ln.Addr()).Msg("tunnel open tcp listener")

	defer ln.Close()

	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		log.Error().Context(ri.LogContext).Str("username", user.Username).Msg("tunnel cannot hijack request")
		http.Error(rw, "Hijack request failed", http.StatusInternalServerError)
		return
	}

	conn, _, err := hijacker.Hijack()
	if !ok {
		log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel hijack request error")
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	// see https://www.ietf.org/archive/id/draft-kazuho-httpbis-reverse-tunnel-00.html
	b := make([]byte, 0, 2048)
	switch req.Header.Get("Connection") {
	case "upgrade", "Upgrade":
		b = fmt.Appendf(b, "HTTP/1.1 101 Switching Protocols\r\n")
		switch req.Header.Get("Upgrade") {
		case "websocket":
			key := sha1.Sum([]byte(req.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
			b = fmt.Appendf(b, "sec-websocket-accept: %s\r\n", base64.StdEncoding.EncodeToString(key[:]))
			b = fmt.Appendf(b, "connection: Upgrade\r\n")
			b = fmt.Appendf(b, "upgrade: websocket\r\n")
		case "reverse":
			b = fmt.Appendf(b, "connection: Upgrade\r\n")
			b = fmt.Appendf(b, "upgrade: reverse\r\n")
		}
		b = append(b, "\r\n"...)
	default:
		b = append(b, "HTTP/1.1 200 OK\r\n\r\n"...)
	}

	_, err = conn.Write(b)
	if !ok {
		log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel send response error")
		return
	}

	session, err := yamux.Client(conn, &yamux.Config{
		AcceptBacklog:          1024,
		EnableKeepAlive:        false,
		KeepAliveInterval:      60 * time.Second,
		ConnectionWriteTimeout: 15 * time.Second,
		MaxStreamWindowSize:    1024 * 1024,
		StreamOpenTimeout:      10 * time.Second,
		StreamCloseTimeout:     10 * time.Second,
		Logger:                 log.DefaultLogger.Std("tunnel", 0),
	})
	if err != nil {
		log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel open yamux session error")
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	defer conn.Close()
	defer session.Close()

	exit := make(chan error, 2)

	go func() {
		for {
			rconn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					log.Error().Err(err).Msg("tunnel listener is closed")
					exit <- err
					return
				}
				log.Error().Err(err).Msg("failed to accept remote connection")
				time.Sleep(10 * time.Millisecond)
				rconn.Close()
				continue
			}

			lconn, err := session.Open()
			if err != nil {
				log.Error().Err(err).Msg("failed to open local session")
				exit <- err
				return
			}

			log.Info().Stringer("remote_addr", rconn.RemoteAddr()).Stringer("local_addr", conn.RemoteAddr()).Msg("tunnel forwarding")

			go func(c1, c2 net.Conn) {
				defer c1.Close()
				defer c2.Close()
				go func() {
					defer c1.Close()
					defer c2.Close()
					_, err := io.Copy(c1, c2)
					if err != nil {
						log.Error().Err(err).Stringer("src_addr", c2.RemoteAddr()).Stringer("dest_addr", c1.RemoteAddr()).Msg("tunnel forwarding error")
					}
				}()
				_, err := io.Copy(c2, c1)
				if err != nil {
					log.Error().Err(err).Stringer("src_addr", c1.RemoteAddr()).Stringer("dest_addr", c2.RemoteAddr()).Msg("tunnel forwarding error")
				}
			}(lconn, rconn)
		}
	}()

	go func() {
		count := 0
		for range time.NewTicker(15 * time.Second).C {
			stream, err := session.OpenStream()
			if err != nil {
				count++
				if count == 3 {
					exit <- err
					break
				}
			} else {
				stream.Close()
				count = 0
			}
		}
	}()

	err = <-exit
	log.Info().Err(err).Msg("tunnel forwarding exit.")
}
