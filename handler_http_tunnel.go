package main

import (
	"cmp"
	"context"
	"encoding/base64"
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

	csvloader *FileLoader[[]Userinfo]
}

func (h *HTTPTunnelHandler) Load() error {
	if strings.HasSuffix(h.Config.Tunnel.AuthTable, ".csv") {
		h.csvloader = &FileLoader[[]Userinfo]{
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

	var user Userinfo
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
	i, ok := slices.BinarySearchFunc(records, user, func(a, b Userinfo) int { return cmp.Compare(a.Username, b.Username) })
	switch {
	case !ok:
		user.AuthError = fmt.Errorf("invalid username: %v", user.Username)
	case user.Password != records[i].Password:
		user.AuthError = fmt.Errorf("wrong password: %v", user.Username)
	default:
		user.AuthError = nil
	}

	if user.AuthError != nil {
		log.Error().Err(user.AuthError).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel user auth failed")
		http.Error(rw, user.AuthError.Error(), http.StatusUnauthorized)
		return
	}

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

	session, err := yamux.Client(conn, nil)
	if err != nil {
		log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel open yamux session error")
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	parts := strings.Split(req.URL.Path, "/")
	addr := net.JoinHostPort(parts[len(parts)-3], parts[len(parts)-2])

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Error().Err(err).Context(ri.LogContext).Str("username", user.Username).Msg("tunnel open tcp listener error")
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Info().Context(ri.LogContext).Str("username", user.Username).Stringer("addr", ln.Addr()).Msg("tunnel open tcp listener")

	go func(ctx context.Context, ln net.Listener, conn net.Conn, session *yamux.Session) {
		defer ln.Close()
		defer conn.Close()
		defer session.Close()
		for {
			rconn, err := ln.Accept()
			if err != nil {
				log.Error().Err(err).Msg("Failed to accept remote connection")
				time.Sleep(10 * time.Millisecond)
				rconn.Close()
				continue
			}

			lconn, err := session.Open()
			if err != nil {
				log.Error().Err(err).Msg("Failed to open local session")
				break
			}

			log.Info().Stringer("remote_addr", rconn.RemoteAddr()).Stringer("local_addr", conn.RemoteAddr()).Msg("tunnel forwarding")

			go func(c1, c2 net.Conn) {
				defer c1.Close()
				defer c2.Close()
				go io.Copy(c1, c2)
				io.Copy(c2, c1)
			}(lconn, rconn)
		}
	}(context.Background(), ln, conn, session)
}
