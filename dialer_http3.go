package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

var _ Dialer = (*HTTP3Dialer)(nil)

type HTTP3Dialer struct {
	Username  string
	Password  string
	Host      string
	Port      string
	UserAgent string
	Resolver  *Resolver

	mu   sync.Mutex
	conn quic.EarlyConnection
}

func (d *HTTP3Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	connect := func() (quic.EarlyConnection, error) {
		host := d.Host
		if d.Resolver != nil {
			if ips, err := d.Resolver.LookupNetIP(ctx, "ip", host); err == nil && len(ips) != 0 {
				host = ips[fastrandn(uint32(len(ips)))].String()
			}
		}
		pconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			return nil, err
		}
		raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, d.Port))
		if err != nil {
			return nil, err
		}
		return quic.DialEarly(ctx,
			pconn,
			raddr,
			&tls.Config{
				NextProtos:         []string{"h3"},
				InsecureSkipVerify: false,
				ServerName:         d.Host,
				ClientSessionCache: tls.NewLRUClientSessionCache(1024),
			},
			&quic.Config{
				DisablePathMTUDiscovery: false,
				EnableDatagrams:         true,
				MaxIncomingUniStreams:   200,
				MaxIncomingStreams:      200,
				// MaxStreamReceiveWindow:     6 * 1024 * 1024,
				// MaxConnectionReceiveWindow: 15 * 1024 * 1024,
			},
		)
	}

	if d.conn == nil {
		d.mu.Lock()
		c, err := connect()
		if err != nil {
			d.mu.Unlock()
			return nil, err
		}
		d.conn = c
		d.mu.Unlock()
	}

	req := &http.Request{
		ProtoMajor: 3,
		Method:     http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   addr,
		},
		Host: addr,
		Header: http.Header{
			"content-type": []string{"application/octet-stream"},
			"user-agent":   []string{d.UserAgent},
		},
		Body:          nil,
		ContentLength: -1,
	}

	if d.Username != "" && d.Password != "" {
		req.Header.Set("proxy-authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(d.Username+":"+d.Password)))
	}

	req = req.WithContext(ctx)

	rt := &http3.SingleDestinationRoundTripper{
		Connection:      d.conn,
		EnableDatagrams: true,
	}

	conn := rt.Start()
	select {
	case <-conn.ReceivedSettings():
	case <-ctx.Done():
		return nil, context.Cause(ctx)
	}

	settings := conn.Settings()
	if !settings.EnableExtendedConnect {
		return nil, errors.New("server didn't enable Extended CONNECT")
	}
	// if !settings.EnableDatagrams {
	// 	return nil, errors.New("server didn't enable HTTP/3 datagram support")
	// }

	stream, err := rt.OpenRequestStream(ctx)
	if err != nil {
		return nil, err
	}
	if err := stream.SendRequestHeader(req); err != nil {
		return nil, err
	}
	resp, err := stream.ReadResponse()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("received status %d", resp.StatusCode)
	}

	return &http3Stream{
		Stream:     stream,
		remoteAddr: d.conn.RemoteAddr(),
		localAddr:  d.conn.LocalAddr(),
	}, nil
}

type http3Stream struct {
	quic.Stream

	remoteAddr net.Addr
	localAddr  net.Addr
}

func (c *http3Stream) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *http3Stream) LocalAddr() net.Addr {
	return c.localAddr
}
