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

	"golang.org/x/net/http2"
)

var _ Dialer = (*HTTP2Dialer)(nil)

type HTTP2Dialer struct {
	Username  string
	Password  string
	Host      string
	Port      string
	UserAgent string

	once      sync.Once
	transport *http2.Transport
}

func (d *HTTP2Dialer) init() {
	if d.UserAgent == "" {
		d.UserAgent = DefaultUserAgent
	}

	d.transport = &http2.Transport{
		DisableCompression: false,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			conn, err := net.Dial("tcp", net.JoinHostPort(d.Host, d.Port))
			if err != nil {
				return nil, err
			}

			tlsConn := tls.Client(conn, &tls.Config{
				NextProtos:         []string{"h2"},
				InsecureSkipVerify: false,
				ServerName:         d.Host,
				ClientSessionCache: tls.NewLRUClientSessionCache(1024),
			})

			err = tlsConn.HandshakeContext(ctx)
			if err != nil {
				return nil, err
			}

			return tlsConn, nil
		},
	}
}

func (d *HTTP2Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.once.Do(d.init)

	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, errors.New("proxy: no support for HTTP proxy connections of type " + network)
	}

	pr, pw := io.Pipe()
	req := &http.Request{
		ProtoMajor: 2,
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

	resp, err := d.transport.RoundTrip(req)
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

	conn := &http2Conn{
		r:      resp.Body,
		w:      pw,
		closed: make(chan struct{}),
	}

	return conn, nil
}

type http2Conn struct {
	r io.ReadCloser
	w io.Writer

	remoteAddr net.Addr
	localAddr  net.Addr

	closed chan struct{}
}

func (c *http2Conn) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *http2Conn) Write(b []byte) (n int, err error) {
	return c.w.Write(b)
}

func (c *http2Conn) Close() (err error) {
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

func (c *http2Conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *http2Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *http2Conn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http2Conn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http2Conn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}
