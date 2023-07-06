package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

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

	once      sync.Once
	transport *http3.RoundTripper
}

func (d *HTTP3Dialer) init() {
	if d.UserAgent == "" {
		d.UserAgent = DefaultHTTPUserAgent
	}

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
					ServerName: d.Host,
					NextProtos: []string{"h3"},
				},
				&quic.Config{
					MaxIncomingStreams: 200,
				},
			)
		},
	}
}

func (d *HTTP3Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.once.Do(d.init)

	pr, pw := io.Pipe()
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
		Body:          pr,
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

	conn := &http3Conn{
		r:      resp.Body,
		w:      pw,
		closed: make(chan struct{}),
	}

	return conn, nil
}

type http3Conn struct {
	r io.ReadCloser
	w io.Writer

	remoteAddr net.Addr
	localAddr  net.Addr

	closed chan struct{}
}

func (c *http3Conn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *http3Conn) Write(b []byte) (n int, err error) {
	return c.w.Write(b)
}

func (c *http3Conn) Close() (err error) {
	select {
	case <-c.closed:
		return
	default:
		close(c.closed)
	}
	if rc, ok := c.r.(io.Closer); ok {
		err = rc.Close()
	}
	if w, ok := c.w.(io.Closer); ok {
		err = w.Close()
	}
	return
}

func (c *http3Conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *http3Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *http3Conn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http3", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http3Conn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http3", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http3Conn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http3", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}
