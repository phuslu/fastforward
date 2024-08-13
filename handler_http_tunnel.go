package main

import (
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/phuslu/log"
)

type HTTPTunnelHandler struct {
	Config        HTTPConfig
	ForwardLogger log.Logger

	csvloader *FileLoader[[]Userinfo]
}

func (h *HTTPTunnelHandler) Load() error {
	if strings.HasSuffix(h.Config.Forward.AuthTable, ".csv") {
		h.csvloader = &FileLoader[[]Userinfo]{
			Filename:     h.Config.Forward.AuthTable,
			Unmarshal:    UserCsvUnmarshal,
			PollDuration: 15 * time.Second,
			ErrorLogger:  log.DefaultLogger.Std("", 0),
		}
		records := h.csvloader.Load()
		if records == nil {
			log.Fatal().Strs("server_name", h.Config.ServerName).Str("auth_table", h.Config.Forward.AuthTable).Msg("load auth_table failed")
		}
		log.Info().Strs("server_name", h.Config.ServerName).Str("auth_table", h.Config.Forward.AuthTable).Int("auth_table_size", len(*records)).Msg("load auth_table ok")
	}

	return nil
}

func (h *HTTPTunnelHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	var user Userinfo
	if s := req.Header.Get("authorization"); s != "" {
		switch t, s, _ := strings.Cut(s, " "); t {
		case "Basic":
			if b, err := base64.StdEncoding.DecodeString(s); err == nil {
				user.Username, user.Password, _ = strings.Cut(string(b), ":")
			}
		}
	}

	hijacker, ok := rw.(http.Hijacker)
	if !ok {
		http.Error(rw, "Hijack request failed", http.StatusInternalServerError)
		return
	}

	conn, _, err := hijacker.Hijack()
	if !ok {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	session, err := yamux.Client(conn, nil)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	parts := strings.Split(req.URL.Path, "/")
	addr := net.JoinHostPort(parts[len(parts)-3], parts[len(parts)-2])

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Info().Msgf("Listening on %s", ln.Addr())

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

			go func(c1, c2 net.Conn) {
				defer c1.Close()
				defer c2.Close()
				go io.Copy(c1, c2)
				io.Copy(c2, c1)
			}(lconn, rconn)
		}
	}(context.Background(), ln, conn, session)
}
