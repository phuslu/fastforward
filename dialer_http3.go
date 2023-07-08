package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/phuslu/log"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type HTTP3Dialer struct {
	Username  string
	Password  string
	Host      string
	Port      string
	UserAgent string
	Resolver  *Resolver

	mu        sync.Mutex
	transport *http3.RoundTripper
}

func (d *HTTP3Dialer) init() {
	if d.transport != nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.transport = &http3.RoundTripper{
		DisableCompression: false,
		EnableDatagrams:    false,
		Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (quic.EarlyConnection, error) {
			host := d.Host
			if d.Resolver != nil {
				if ips, err := d.Resolver.LookupIP(ctx, host); err == nil && len(ips) != 0 {
					host = ips[log.Fastrandn(uint32(len(ips)))].String()
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
					MaxIncomingUniStreams:   200,
					MaxIncomingStreams:      200,
					DisablePathMTUDiscovery: false,
					EnableDatagrams:         false,
				},
			)
		},
	}

	if d.UserAgent == "" {
		d.UserAgent = DefaultHTTPUserAgent
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

	resp, err := d.transport.RoundTripOpt(req, http3.RoundTripOpt{DontCloseRequestStream: true})
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		var errmsg string
		if resp.Body != nil {
			data := make([]byte, 1024)
			if n, err := resp.Body.Read(data); err != nil {
				errmsg = err.Error()
			} else {
				errmsg = string(data[:n])
			}
		}
		return nil, errors.New("proxy: read from " + d.Host + " error: " + resp.Status + ": " + errmsg)
	}

	streamer, ok := resp.Body.(http3.HTTPStreamer)
	if !ok {
		return nil, errors.New("proxy: read from " + d.Host + " error: resp body not implemented http3.HTTPStreamer")
	}

	return &http3Conn{streamer.HTTPStream()}, nil
}

type http3Conn struct {
	quic.Stream
}

func (c *http3Conn) LocalAddr() net.Addr {
	return c.LocalAddr()
}

func (c *http3Conn) RemoteAddr() net.Addr {
	return c.RemoteAddr()
}
