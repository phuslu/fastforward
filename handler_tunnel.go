package main

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

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
		// Connect to the SSH server
		ln, err := h.tunnel(ctx)
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

func (h *TunnelHandler) tunnel(ctx context.Context) (net.Listener, error) {
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

	lconn, err := h.LocalDialer.DialContext(ctx, "tcp", laddr)
	if err != nil {
		log.Error().Err(err).Msgf("Fail to dial %v", laddr)
	}

	go io.Copy(rconn, lconn)
	io.Copy(lconn, rconn)
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
