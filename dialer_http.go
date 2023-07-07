package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
)

const (
	DefaultHTTPUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
)

var _ Dialer = (*HTTPDialer)(nil)

type HTTPDialer struct {
	Username  string
	Password  string
	Host      string
	Port      string
	UserAgent string
	TLSConfig *tls.Config
	Dialer    Dialer

	mu sync.Mutex
}

func (d *HTTPDialer) init() {
	if d.Dialer != nil && d.UserAgent != "" {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if d.Dialer == nil {
		d.Dialer = &LocalDialer{}
	}

	if d.UserAgent == "" {
		d.UserAgent = DefaultHTTPUserAgent
	}
}

var CRLFCRLF = []byte{'\r', '\n', '\r', '\n'}

func (d *HTTPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.init()

	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, errors.New("proxy: no support for HTTP proxy connections of type " + network)
	}

	conn, err := d.Dialer.DialContext(ctx, network, net.JoinHostPort(d.Host, d.Port))
	if err != nil {
		return nil, err
	}
	closeConn := &conn
	defer func() {
		if closeConn != nil {
			(*closeConn).Close()
		}
	}()

	if d.TLSConfig != nil {
		tlsConn := tls.Client(conn, d.TLSConfig)
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}
		conn = tlsConn
	}

	buf := make([]byte, 0, 2048)

	buf = fmt.Appendf(buf, "CONNECT %s HTTP/1.1\r\n", addr)
	buf = fmt.Appendf(buf, "Host: %s\r\n", addr)
	buf = fmt.Appendf(buf, "User-Agent: %s\r\n", d.UserAgent)
	if d.Username != "" {
		buf = fmt.Appendf(buf, "Proxy-Authorization: Basic %s\r\n", base64.StdEncoding.EncodeToString([]byte(d.Username+":"+d.Password)))
	}
	buf = fmt.Appendf(buf, "\r\n")

	if _, err := conn.Write(buf); err != nil {
		return nil, errors.New("proxy: failed to write greeting to HTTP proxy at " + d.Host + ": " + err.Error())
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
		return nil, fmt.Errorf("proxy: failed to connect %s via %s: %s", addr, d.Host, bytes.TrimRight(b, "\x00"))
	}
	for i, c := range b[n+1:] {
		if i == 3 || c < '0' || c > '9' {
			break
		}
		status = status*10 + int(c-'0')
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("proxy: failed to connect %s via %s: %s", addr, d.Host, bytes.TrimRight(b, "\x00"))
	}

	closeConn = nil
	return conn, nil
}
