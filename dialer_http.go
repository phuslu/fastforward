package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
)

const (
	DefaultHTTPDialerUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/68.0.3440.106 Safari/537.36"
)

var (
	CRLF     = []byte{0x0d, 0x0a}
	CRLFCRLF = []byte{0x0d, 0x0a, 0x0d, 0x0a}
)

type HTTPDialer struct {
	Username  string
	Password  string
	Host      string
	Port      string
	UserAgent string
	Dialer    *Dialer

	once sync.Once
}

func (d *HTTPDialer) init() {
	if d.UserAgent == "" {
		d.UserAgent = DefaultHTTPDialerUserAgent
	}
	if d.Dialer == nil {
		d.Dialer = &Dialer{}
	}
}

func (d *HTTPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.once.Do(d.init)

	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, errors.New("proxy: no support for HTTP proxy connections of type " + network)
	}

	conn, err := d.DialContext(ctx, network, net.JoinHostPort(d.Host, d.Port))
	if err != nil {
		return nil, err
	}
	closeConn := &conn
	defer func() {
		if closeConn != nil {
			(*closeConn).Close()
		}
	}()

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, errors.New("proxy: failed to parse port number: " + portStr)
	}
	if port < 1 || port > 0xffff {
		return nil, errors.New("proxy: port number out of range: " + portStr)
	}

	if d.Dialer.Resolver != nil {
		hosts, err := d.Dialer.Resolver.LookupHost(ctx, host)
		if err == nil && len(hosts) > 0 {
			host = hosts[0]
		}
	}

	var b bytes.Buffer

	fmt.Fprintf(&b, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\n", host, portStr, host, portStr)
	if d.Username != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: Basic %s\r\n", base64.StdEncoding.EncodeToString([]byte(d.Username+":"+d.Password)))
	}
	io.WriteString(&b, "\r\n")

	bb := b.Bytes()

	if _, err := conn.Write(bb); err != nil {
		return nil, errors.New("proxy: failed to write greeting to HTTP proxy at " + d.Host + ": " + err.Error())
	}

	buf := make([]byte, 2048)
	b0 := buf
	total := 0

	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		total += n
		buf = buf[n:]

		if i := bytes.Index(b0, CRLFCRLF); i > 0 {
			conn = &ConnWithData{conn, b0[i+4 : total]}
			b0 = b0[:i+4]
			break
		}
	}

	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(b0)), nil)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("proxy: failed to read greeting from HTTP proxy at " + d.Host + ": " + resp.Status)
	}

	closeConn = nil
	return conn, nil
}
