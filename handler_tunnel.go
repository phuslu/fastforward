package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/libp2p/go-yamux"
	"github.com/phuslu/log"
	"github.com/puzpuzpuz/xsync/v3"
	"golang.org/x/crypto/ssh"
)

type TunnelHandler struct {
	Config          TunnelConfig
	MemoryListeners *xsync.MapOf[string, *MemoryListener]
	Resolver        *Resolver
	LocalDialer     Dialer
	Dialers         map[string]string
}

func (h *TunnelHandler) Load() error {
	if len(h.Config.Listen) != 1 {
		return fmt.Errorf("invalid tunnel listen: %v", h.Config.Listen)
	}
	return nil
}

func (h *TunnelHandler) Serve(ctx context.Context) {
	loop := func() bool {
		var tunnel func(context.Context, string) (net.Listener, error)
		dialer := h.Dialers[h.Config.Dialer]
		switch strings.Split(dialer, "://")[0] {
		case "ssh", "ssh2":
			tunnel = h.sshtunnel
		case "http", "https", "ws", "wss":
			tunnel = h.wstunnel
		default:
			log.Fatal().Str("dialer", dialer).Msg("dialer tunnel is unsupported")
		}
		ln, err := tunnel(ctx, dialer)
		if err != nil {
			log.Error().Err(err).Msgf("Failed to listen %s", h.Config.Listen[0])
			time.Sleep(2 * time.Second)
			return true
		}

		defer ln.Close()

		log.Info().Msgf("Listening on remote %s", h.Config.Listen[0])

		// Accept connections from the remote side
		for {
			rconn, err := ln.Accept()
			if err != nil || rconn == nil || reflect.ValueOf(rconn).IsNil() {
				log.Error().Err(err).Any("rconn", rconn).Msg("Failed to accept remote connection")
				time.Sleep(10 * time.Millisecond)
				ln.Close()
				return true
			}

			go h.handle(ctx, rconn, h.Config.ProxyPass)
		}
	}

	for loop() {
		delay := time.Duration(5+log.Fastrandn(10)) * time.Second
		log.Info().Stringer("delay", delay).Msg("tunnel loop...")
		time.Sleep(delay)
	}

	return
}

func (h *TunnelHandler) sshtunnel(ctx context.Context, dialer string) (net.Listener, error) {
	log.Info().Str("dialer", dialer).Msg("connecting tunnel host")

	u, err := url.Parse(dialer)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("no user info in dialer: %s", dialer)
	}

	config := &ssh.ClientConfig{
		User: u.User.Username(),
		Auth: []ssh.AuthMethod{
			ssh.Password(first(u.User.Password())),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         60 * time.Second,
	}
	if key := u.Query().Get("key"); key != "" {
		data, err := os.ReadFile(key)
		if err != nil {
			log.Error().Err(err).Msgf("failed to read ssh key %s", key)
			return nil, err
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			log.Error().Err(err).Msgf("invalid ssh key %s", data)
			return nil, fmt.Errorf("invalid ssh key %s: %w", data, err)
		}
		config.Auth = append([]ssh.AuthMethod{ssh.PublicKeys(signer)}, config.Auth...)
	}

	hostport := u.Host
	if _, _, err := net.SplitHostPort(hostport); err != nil {
		hostport = net.JoinHostPort(hostport, "22")
	}
	if resolve := u.Query().Get("resolve"); resolve != "" {
		_, port, _ := net.SplitHostPort(hostport)
		hostport = net.JoinHostPort(resolve, port)
	}

	conn, err := (&net.Dialer{Timeout: time.Duration(h.Config.DialTimeout) * time.Second}).DialContext(ctx, "tcp", hostport)
	if err != nil {
		log.Error().Err(err).Msgf("failed to dial %s", hostport)
		return nil, fmt.Errorf("failed to dial %s: %w", hostport, err)
	}

	c, chans, reqs, err := ssh.NewClientConn(conn, hostport, config)
	if err != nil {
		log.Error().Err(err).Msgf("failed to create ssh conn %s", hostport)
		return nil, fmt.Errorf("failed to create ssh conn %s: %w", hostport, err)
	}

	client := ssh.NewClient(c, chans, reqs)

	// Set up the remote listener
	ln, err := client.Listen("tcp", h.Config.Listen[0])
	if err != nil {
		log.Error().Err(err).Msgf("failed to listen %s", h.Config.Listen[0])
		client.Close()
		return nil, fmt.Errorf("failed to dial %s: %w", h.Config.Listen[0], err)
	}

	if tc, _ := conn.(*net.TCPConn); conn != nil && h.Config.SpeedLimit > 0 {
		err := SetTcpMaxPacingRate(tc, int(h.Config.SpeedLimit))
		log.DefaultLogger.Err(err).Str("tunnel_proxy_pass", h.Config.ProxyPass).Str("tunnel_dialer_name", h.Config.Dialer).Int64("tunnel_speedlimit", h.Config.SpeedLimit).Msg("set speedlimit")
	}

	return &TunnelListener{ln, client}, nil
}

func (h *TunnelHandler) wstunnel(ctx context.Context, dialer string) (net.Listener, error) {
	log.Info().Str("dialer", dialer).Msg("connecting tunnel host")

	ctx, cancel := context.WithTimeout(ctx, time.Duration(h.Config.DialTimeout)*time.Second)
	defer cancel()

	u, err := url.Parse(dialer)
	if err != nil {
		return nil, err
	}
	if u.User == nil {
		return nil, fmt.Errorf("no user info in dialer: %s", dialer)
	}

	host, port, ech := u.Hostname(), u.Port(), []byte{}
	if u.Query().Get("ech") == "true" {
		https, err := h.Resolver.LookupHTTPS(ctx, host)
		log.Debug().Str("dns_server", h.Resolver.Addr).Interface("https", https).AnErr("error", err).Msg("lookup https records")
		if len(https) == 0 && err == nil {
			err = fmt.Errorf("lookup https %v error: emtpy record", host)
		}
		if err != nil {
			log.Error().Err(err).Str("tunnel_host", host).Stringer("tunnel_url", u).Msg("lookup https error")
			return nil, err
		}
		if len(https[0].ECH) > 0 {
			ech = https[0].ECH
		}
		switch {
		case len(https[0].IPv4Hint) > 0:
			host = https[0].IPv4Hint[0].String()
		case len(https[0].IPv6Hint) > 0:
			host = https[0].IPv6Hint[0].String()
		}
	}
	if resolve := u.Query().Get("resolve"); resolve != "" {
		host = resolve
	}
	if _, err := netip.ParseAddr(host); err != nil {
		ips, err := h.Resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		host = ips[0].String()
	}
	if port == "" {
		switch u.Scheme {
		case "http,", "ws":
			port = "80"
		default:
			port = "443"
		}
	}

	hostport := net.JoinHostPort(host, port)

	conn, err := h.LocalDialer.DialContext(ctx, "tcp", hostport)
	if err != nil {
		log.Error().Err(err).Str("tunnel_host", hostport).Msg("connect tunnel host error")
		return nil, err
	}

	if tc, ok := conn.(*net.TCPConn); ok {
		config := net.KeepAliveConfig{
			Enable:   true,
			Idle:     15 * time.Second,
			Interval: 15 * time.Second,
			Count:    3,
		}
		err := tc.SetKeepAliveConfig(config)
		log.DefaultLogger.Err(err).Str("tunnel_host", hostport).Any("keepalive_config", config).Msg("set tunnel host keepalive")
		if h.Config.SpeedLimit > 0 {
			err := SetTcpMaxPacingRate(tc, int(h.Config.SpeedLimit))
			log.DefaultLogger.Err(err).Str("tunnel_host", hostport).Any("tunnel_speedlimit", h.Config.SpeedLimit).Msg("set tunnel speedlimit")
		}
	}

	switch u.Scheme {
	case "https", "wss":
		tlsConfig := &tls.Config{
			NextProtos:         []string{"http/1.1"},
			InsecureSkipVerify: u.Query().Get("insecure") == "true",
			ServerName:         u.Hostname(),
		}
		if len(ech) > 0 {
			tlsConfig.MinVersion = tls.VersionTLS13
			tlsConfig.EncryptedClientHelloConfigList = ech
		}
		tlsConn := tls.Client(conn, tlsConfig)
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			_ = conn.Close()
			log.Error().Err(err).Str("tunnel_host", hostport).Msg("handshake tunnel host error")
			return nil, err
		}
		conn = tlsConn
	}

	targetHost, targetPort, err := net.SplitHostPort(h.Config.Listen[0])
	if err != nil {
		return nil, fmt.Errorf("invalid remote addr: %s", h.Config.Listen[0])
	}

	// see https://www.ietf.org/archive/id/draft-kazuho-httpbis-reverse-tunnel-00.html
	buf := make([]byte, 0, 2048)
	buf = fmt.Appendf(buf, "GET /.well-known/reverse/tcp/%s/%s/ HTTP/1.1\r\n", targetHost, targetPort)
	buf = fmt.Appendf(buf, "Host: %s\r\n", u.Hostname())
	buf = fmt.Appendf(buf, "Authorization: Basic %s\r\n", base64.StdEncoding.EncodeToString([]byte(u.User.Username()+":"+first(u.User.Password()))))
	buf = fmt.Appendf(buf, "User-Agent: %s\r\n", DefaultUserAgent)
	switch u.Scheme {
	case "ws", "wss":
		buf = fmt.Appendf(buf, "Connection: Upgrade\r\n")
		buf = fmt.Appendf(buf, "Upgrade: websocket\r\n")
		buf = fmt.Appendf(buf, "Sec-WebSocket-Version: 13\r\n")
		buf = fmt.Appendf(buf, "Sec-WebSocket-Key: %s\r\n", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%x%x\n", fastrandn(1<<32-1), fastrandn(1<<32-1)))))
	default:
		buf = fmt.Appendf(buf, "Connection: Upgrade\r\n")
		buf = fmt.Appendf(buf, "Upgrade: reverse\r\n")
	}
	buf = fmt.Appendf(buf, "\r\n")

	log.Info().Stringer("tunnel_conn_addr", conn.RemoteAddr()).Bytes("request_body", buf).Msg("send tunnel request")

	// conn.SetDeadline(time.Now().Add(time.Duration(h.Config.DialTimeout) * time.Second))
	_, err = conn.Write(buf)
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

	for {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
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
		return nil, fmt.Errorf("tunnel: failed to tunnel %s via %s: %s", h.Config.Listen[0], conn.RemoteAddr().String(), bytes.TrimRight(b, "\x00"))
	}
	for i, c := range b[n+1:] {
		if i == 3 || c < '0' || c > '9' {
			break
		}
		status = status*10 + int(c-'0')
	}
	if status != http.StatusOK && status != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("tunnel: failed to tunnel %s via %s: %s", h.Config.Listen[0], conn.RemoteAddr().String(), bytes.TrimRight(b, "\x00"))
	}

	ln, err := yamux.Server(conn, &yamux.Config{
		AcceptBacklog:          256,
		PingBacklog:            32,
		EnableKeepAlive:        true,
		KeepAliveInterval:      30 * time.Second,
		ConnectionWriteTimeout: 10 * time.Second,
		MaxStreamWindowSize:    256 * 1024,
		LogOutput:              SlogWriter{Logger: log.DefaultLogger.Slog()},
		ReadBufSize:            4096,
		MaxMessageSize:         64 * 1024, // Means 64KiB/10s = 52kbps minimum speed.
		WriteCoalesceDelay:     100 * time.Microsecond,
	})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("tunnel: open yamux server on remote %s: %w", h.Config.Listen[0], err)
	}

	return &TunnelListener{ln, conn}, nil
}

func (h *TunnelHandler) handle(ctx context.Context, rconn net.Conn, laddr string) {
	if h.MemoryListeners != nil {
		if ln, ok := h.MemoryListeners.Load(h.Config.Listen[0]); ok && ln != nil {
			log.Info().Str("remote_host", rconn.RemoteAddr().String()).Str("local_addr", ln.Addr().String()).Msg("tunnel handler memory listener local addr")
			ln.Add(rconn)
			return
		}
	}

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
		return
	}
	defer lconn.Close()

	go func() {
		defer rconn.Close()
		defer lconn.Close()
		_, err := io.Copy(rconn, lconn)
		if err != nil && !errors.Is(err, net.ErrClosed) {
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
