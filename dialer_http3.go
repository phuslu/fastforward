package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"sync/atomic"

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

	mu        sync.Mutex
	transport atomic.Value // *http3.RoundTripper
}

func (d *HTTP3Dialer) init() {
	if d.transport.Load() != nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.transport.Load() != nil {
		return
	}

	d.transport.Store(&http3.RoundTripper{
		DisableCompression: false,
		EnableDatagrams:    false,
		Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (quic.EarlyConnection, error) {
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
					EnableDatagrams:         false,
					MaxIncomingUniStreams:   200,
					MaxIncomingStreams:      200,
					// MaxStreamReceiveWindow:     6 * 1024 * 1024,
					// MaxConnectionReceiveWindow: 15 * 1024 * 1024,
				},
			)
		},
	})

	if d.UserAgent == "" {
		d.UserAgent = DefaultUserAgent
	}
}

func (d *HTTP3Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.init()

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

	var remoteAddr, localAddr net.Addr

	req = req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr, localAddr = connInfo.Conn.RemoteAddr(), connInfo.Conn.LocalAddr()
		},
	}))

	resp, err := d.transport.Load().(*http3.RoundTripper).RoundTripOpt(req, http3.RoundTripOpt{OnlyCachedConn: false})
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, errors.New("proxy: read from " + d.Host + " error: " + resp.Status + ": " + string(data))
	}

	streamer, ok := resp.Body.(http3.HTTPStreamer)
	if !ok {
		return nil, errors.New("proxy: read from " + d.Host + " error: resp body not implemented http3.HTTPStreamer")
	}

	if remoteAddr == nil || localAddr == nil {
		remoteAddr, localAddr = &net.UDPAddr{}, &net.UDPAddr{}
	}

	return &http3Stream{
		Stream:     streamer.HTTPStream(),
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
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
