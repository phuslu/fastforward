package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/valyala/bytebufferpool"
)

var _ Dialer = (*DoHResolverDialer)(nil)

type DoHResolverDialer struct {
	EndPoint  string
	UserAgent string
	Timeout   time.Duration
	Transport http.RoundTripper
}

func (d *DoHResolverDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	return &dohConn{dialer: d}, nil
}

type dohConn struct {
	dialer *DoHResolverDialer
	buffer *bytebufferpool.ByteBuffer
	data   []byte
}

func (c *dohConn) Read(b []byte) (n int, err error) {
	if c.data == nil {
		err = io.ErrUnexpectedEOF
		return
	}

	n = copy(b, c.data)
	if n < len(c.data) {
		c.data = c.data[n:]
	} else {
		c.data = nil
		bytebufferpool.Put(c.buffer)
	}

	return n, nil
}

func (c *dohConn) Write(b []byte) (n int, err error) {
	if len(b) < 2 {
		return 0, errors.New("dns message too short")
	}
	if int(binary.BigEndian.Uint16(b))+2 != len(b) {
		return 0, errors.New("dns message head size mismath")
	}

	req, err := http.NewRequest(http.MethodPost, c.dialer.EndPoint, bytes.NewReader(b[2:]))
	if err != nil {
		return 0, err
	}

	req.Header.Set("content-type", "application/dns-message")
	if c.dialer.UserAgent != "" {
		req.Header.Set("user-agent", c.dialer.UserAgent)
	}

	var tr = c.dialer.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}

	timeout := c.dialer.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(req.Context(), timeout)
	defer cancel()

	resp, err := tr.RoundTrip(req.WithContext(ctx))
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK || resp.ContentLength <= 0 {
		var errmsg string
		if resp.Body != nil {
			data := make([]byte, 1024)
			if n, err := resp.Body.Read(data); err != nil {
				errmsg = err.Error()
			} else {
				errmsg = string(data[:n])
			}
		}
		return 0, errors.New("proxy: read from " + c.dialer.EndPoint + " error: " + resp.Status + ": " + errmsg)
	}

	c.buffer = bytebufferpool.Get()
	binary.Write(c.buffer, binary.BigEndian, uint16(resp.ContentLength))
	_, err = io.Copy(c.buffer, resp.Body)
	if err != nil {
		return 0, err
	}
	c.data = c.buffer.B

	return len(b), nil
}

func (c *dohConn) Close() (err error) {
	return
}

func (c *dohConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (c *dohConn) RemoteAddr() (addr net.Addr) {
	return &net.TCPAddr{}
}

func (c *dohConn) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *dohConn) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *dohConn) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http2", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}
