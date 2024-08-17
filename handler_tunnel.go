package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/yamux"
	"github.com/phuslu/log"
	"golang.org/x/crypto/ssh"
)

type TunnelHandler struct {
	Config        TunnelConfig
	ForwardLogger log.Logger
	GeoResolver   *GeoResolver
	LocalDialer   Dialer
}

func (h *TunnelHandler) Load() error {
	return nil
}

func (h *TunnelHandler) Serve(ctx context.Context) {
	loop := func() bool {
		tunnel := h.sshtunnel
		if h.Config.SSH.Host == "" && h.Config.HTTPS.Host != "" {
			tunnel = h.httptunnel
		}
		ln, err := tunnel(ctx)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to listen %s", h.Config.RemoteAddr)
			time.Sleep(2 * time.Second)
			return true
		}

		defer ln.Close()

		log.Info().Msgf("Listening on remote %s", h.Config.RemoteAddr)

		// Accept connections from the remote side
		for {
			rconn, err := ln.Accept()
			if err != nil {
				log.Error().Err(err).Msg("Failed to accept remote connection")
				time.Sleep(10 * time.Millisecond)
				ln.Close()
				return true
			}

			go h.handle(ctx, rconn, h.Config.LocalAddr)
		}
	}

	for loop() {
		log.Info().Msg("tunnel loop...")
	}

	return
}

func (h *TunnelHandler) sshtunnel(ctx context.Context) (net.Listener, error) {
	config := &ssh.ClientConfig{
		User: h.Config.SSH.User,
		Auth: []ssh.AuthMethod{
			ssh.Password(h.Config.SSH.Password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         60 * time.Second,
	}
	if h.Config.SSH.Key != "" {
		signer, err := ssh.ParsePrivateKey([]byte(h.Config.SSH.Key))
		if err != nil {
			log.Error().Err(err).Msgf("invalid ssh key %s", h.Config.SSH.Key)
			return nil, fmt.Errorf("invalid ssh key %s: %w", h.Config.SSH.Key, err)
		}
		config.Auth = append([]ssh.AuthMethod{ssh.PublicKeys(signer)}, config.Auth...)
	}

	hostport := fmt.Sprintf("%s:%d", h.Config.SSH.Host, cmp.Or(h.Config.SSH.Port, 22))
	lconn, err := ssh.Dial("tcp", hostport, config)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to dial %s", hostport)
		return nil, fmt.Errorf("invalid ssh key %s: %w", h.Config.SSH.Key, err)
	}

	// Set up the remote listener
	ln, err := lconn.Listen("tcp", h.Config.RemoteAddr)
	if err != nil {
		log.Error().Err(err).Msgf("Failed to listen %s", h.Config.RemoteAddr)
		lconn.Close()
		return nil, fmt.Errorf("invalid ssh key %s: %w", h.Config.SSH.Key, err)
	}

	return &TunnelListener{ln, lconn}, nil
}

func (h *TunnelHandler) httptunnel(ctx context.Context) (net.Listener, error) {
	log.Info().Str("tunnel_host", h.Config.HTTPS.Host).Int("tunnel_port", h.Config.HTTPS.Port).Msg("connect tunnel host")

	ctx1, cancel := context.WithTimeout(ctx, time.Duration(h.Config.DialTimeout)*time.Second)
	defer cancel()

	conn, err := h.LocalDialer.DialContext(ctx1, "tcp", net.JoinHostPort(h.Config.HTTPS.Host, strconv.Itoa(h.Config.HTTPS.Port)))
	if err != nil {
		log.Error().Err(err).Str("tunnel_host", h.Config.HTTPS.Host).Int("tunnel_port", h.Config.HTTPS.Port).Msg("connect tunnel host error")
		return nil, err
	}

	tlsConn := tls.Client(conn, &tls.Config{
		NextProtos:         []string{"http/1.1"},
		InsecureSkipVerify: h.Config.HTTPS.Insecure,
		ServerName:         h.Config.HTTPS.Host,
	})
	err = tlsConn.HandshakeContext(ctx1)
	if err != nil {
		_ = conn.Close()
		log.Error().Err(err).Str("tunnel_host", h.Config.HTTPS.Host).Int("tunnel_port", h.Config.HTTPS.Port).Msg("handshake tunnel host error")
		return nil, err
	}

	i := strings.LastIndexByte(h.Config.RemoteAddr, ':')
	if i < 0 || i == len(h.Config.RemoteAddr)-1 {
		return nil, fmt.Errorf("invalid remote addr: %s", h.Config.RemoteAddr)
	}

	buf := make([]byte, 0, 2048)
	buf = fmt.Appendf(buf, "GET /.well-known/reverse/tcp/%s/%s/ HTTP/1.0\r\n", h.Config.RemoteAddr[:i], h.Config.RemoteAddr[i+1:])
	buf = fmt.Appendf(buf, "Host: %s\r\n", h.Config.HTTPS.Host)
	buf = fmt.Appendf(buf, "Authorization: Basic %s\r\n", base64.StdEncoding.EncodeToString([]byte(h.Config.HTTPS.User+":"+h.Config.HTTPS.Password)))
	buf = fmt.Appendf(buf, "User-Agent: %s\r\n", DefaultUserAgent)
	buf = fmt.Appendf(buf, "Content-Type: application/octet-stream\r\n")
	buf = fmt.Appendf(buf, "\r\n")

	log.Info().Stringer("tunnel_conn_addr", tlsConn.RemoteAddr()).Bytes("request_body", buf).Msg("send tunnel request")

	_, err = tlsConn.Write(buf)
	if err != nil {
		return nil, err
	}

	// see https://github.com/golang/go/issues/5373
	buf = buf[:cap(buf)]
	for i := range buf {
		buf[i] = 0
	}

	b := buf
	total := 0

	conn = tlsConn
	// conn.SetDeadline(time.Now().Add(time.Duration(h.Config.DialTimeout) * time.Second))

	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		total += n
		buf = buf[n:]

		if i := bytes.Index(b, CRLFCRLF); i > 0 {
			if i+4 < total {
				conn = &ConnWithData{conn, b[i+4 : total]}
			}
			break
		}
	}

	status := 0
	n := bytes.IndexByte(b, ' ')
	if n < 0 {
		return nil, fmt.Errorf("tunnel: failed to tunnel %s via %s: %s", h.Config.RemoteAddr, conn.RemoteAddr().String(), bytes.TrimRight(b, "\x00"))
	}
	for i, c := range b[n+1:] {
		if i == 3 || c < '0' || c > '9' {
			break
		}
		status = status*10 + int(c-'0')
	}
	if status != http.StatusOK && status != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("tunnel: failed to tunnel %s via %s: %s", h.Config.RemoteAddr, conn.RemoteAddr().String(), bytes.TrimRight(b, "\x00"))
	}

	conn.SetDeadline(time.Time{})

	ln, err := yamux.Server(conn, nil)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tunnel: open yamux server on remote %s: %w", h.Config.RemoteAddr, err)
	}

	return &TunnelListener{ln, conn}, nil
}

func (h *TunnelHandler) handle(ctx context.Context, rconn net.Conn, laddr string) {
	defer rconn.Close()

	rhost, _, _ := net.SplitHostPort(rconn.RemoteAddr().String())
	ctx = context.WithValue(ctx, DialerHTTPHeaderContextKey, http.Header{
		"X-Forwarded-For": []string{rhost},
	})

	if h.Config.DialTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(h.Config.DialTimeout)*time.Second)
		defer cancel()
	}

	log.Info().Str("remote_host", rhost).Str("local_addr", laddr).Msg("tunnel handler connect local addr")
	lconn, err := h.LocalDialer.DialContext(ctx, "tcp", laddr)
	if err != nil {
		log.Error().Err(err).Msgf("Fail to dial %v", laddr)
	}
	defer lconn.Close()

	go func() {
		defer rconn.Close()
		defer lconn.Close()
		_, err := io.Copy(rconn, lconn)
		if err != nil {
			log.Error().Err(err).Stringer("src_addr", lconn.RemoteAddr()).Stringer("dest_addr", rconn.RemoteAddr()).Msg("tunnel forwarding error")
		}
	}()

	_, err = io.Copy(lconn, rconn)
	if err != nil {
		log.Error().Err(err).Stringer("src_addr", rconn.RemoteAddr()).Stringer("dest_addr", lconn.RemoteAddr()).Msg("tunnel forwarding error")
	}
}

type TunnelListener struct {
	net.Listener
	Closer io.Closer
}

func (ln *TunnelListener) Close() (err error) {
	if e := ln.Listener.Close(); e != nil {
		err = e
	}
	if e := ln.Closer.Close(); e != nil {
		err = e
	}
	return
}
