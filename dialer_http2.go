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
	Dialer    Dialer

	mu        sync.Mutex
	transport *http2.Transport
}

func (d *HTTP2Dialer) init() {
	if d.transport != nil {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.transport != nil {
		return
	}

	d.transport = &http2.Transport{
		DisableCompression: false,
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			dialer := d.Dialer
			if dialer == nil {
				dialer = &net.Dialer{}
			}
			conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(d.Host, d.Port))
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

	if d.UserAgent == "" {
		d.UserAgent = DefaultUserAgent
	}
}

func (d *HTTP2Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.init()

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

	var remoteAddr, localAddr net.Addr

	req = req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr, localAddr = connInfo.Conn.RemoteAddr(), connInfo.Conn.LocalAddr()
		},
	}))

	resp, err := d.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, errors.New("proxy: read from " + d.Host + " error: " + resp.Status + ": " + string(data))
	}

	if remoteAddr == nil || localAddr == nil {
		remoteAddr, localAddr = &net.TCPAddr{}, &net.TCPAddr{}
	}

	conn := &http2Stream{
		r:          resp.Body,
		w:          pw,
		closed:     make(chan struct{}),
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}

	return conn, nil
}

type http2Stream struct {
	r io.ReadCloser
	w io.Writer

	closed chan struct{}

	remoteAddr net.Addr
	localAddr  net.Addr
}

func (c *http2Stream) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *http2Stream) Write(b []byte) (n int, err error) {
	return c.w.Write(b)
}

func (c *http2Stream) Close() (err error) {
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

func (c *http2Stream) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *http2Stream) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *http2Stream) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http2Stream) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http2Stream) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}
