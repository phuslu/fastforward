package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

var _ Dialer = (*HTTPDialer)(nil)

type HTTPDialer struct {
	Username   string
	Password   string
	Host       string
	Port       string
	TLS        bool
	Websocket  bool
	Insecure   bool
	UserAgent  string
	CACert     string
	ClientKey  string
	ClientCert string
	Dialer     Dialer

	mu        sync.Mutex
	tlsConfig *tls.Config
}

func (d *HTTPDialer) init() error {
	if !d.TLS || d.tlsConfig != nil {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	d.tlsConfig = &tls.Config{
		InsecureSkipVerify: d.Insecure,
		ServerName:         d.Host,
		ClientSessionCache: tls.NewLRUClientSessionCache(1024),
	}
	if d.CACert != "" && d.ClientKey != "" && d.ClientCert != "" {
		caData, err := os.ReadFile(d.CACert)
		if err != nil {
			return err
		}

		cert, err := tls.LoadX509KeyPair(d.ClientCert, d.ClientKey)
		if err != nil {
			return err
		}

		d.tlsConfig.RootCAs = x509.NewCertPool()
		d.tlsConfig.RootCAs.AppendCertsFromPEM(caData)
		d.tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return nil
}

var CRLFCRLF = []byte{'\r', '\n', '\r', '\n'}

func (d *HTTPDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := d.init(); err != nil {
		return nil, err
	}

	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, errors.New("httpdialer: no support for HTTP proxy connections of type " + network)
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

	if d.TLS {
		if d.tlsConfig == nil {
			return nil, errors.New("httpdialer: empty tls config")
		}
		tlsConn := tls.Client(conn, d.tlsConfig)
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			return nil, err
		}
		conn = tlsConn
	}

	buf := make([]byte, 0, 2048)

	if !d.Websocket {
		buf = fmt.Appendf(buf, "CONNECT %s HTTP/1.1\r\n", addr)
		buf = fmt.Appendf(buf, "Host: %s\r\n", addr)
	} else {
		host, port, _ := net.SplitHostPort(addr)
		key := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%x%x\n", fastrandn(1<<32-1), fastrandn(1<<32-1))))
		buf = fmt.Appendf(buf, "GET /.well-known/connect/tcp/%s/%s/ HTTP/1.1\r\n", host, port)
		buf = fmt.Appendf(buf, "Host: %s\r\n", d.Host)
		buf = fmt.Appendf(buf, "Connection: Upgrade\r\n")
		buf = fmt.Appendf(buf, "Upgrade: websocket\r\n")
		buf = fmt.Appendf(buf, "Sec-WebSocket-Version: 13\r\n")
		buf = fmt.Appendf(buf, "Sec-WebSocket-Key: %s\r\n", key)
	}
	if d.Username != "" {
		buf = fmt.Appendf(buf, "Proxy-Authorization: Basic %s\r\n", base64.StdEncoding.EncodeToString([]byte(d.Username+":"+d.Password)))
	}
	if header, _ := ctx.Value(DialerHTTPHeaderContextKey).(http.Header); header != nil {
		for key, values := range header {
			for _, value := range values {
				fmt.Appendf(buf, "%s: %s\r\n", key, value)
			}
		}
	}
	buf = fmt.Appendf(buf, "User-Agent: %s\r\n", cmp.Or(d.UserAgent, DefaultUserAgent))
	buf = fmt.Appendf(buf, "\r\n")

	if _, err := conn.Write(buf); err != nil {
		return nil, errors.New("httpdialer: failed to write greeting to HTTP proxy at " + d.Host + ": " + err.Error())
	}

	// see https://github.com/golang/go/issues/5373
	buf = buf[:cap(buf)]
	for i := range buf {
		buf[i] = 0
	}

	b := buf
	total := 0

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}

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
		return nil, fmt.Errorf("httpdialer: failed to connect %s via %s: %s", addr, d.Host, bytes.TrimRight(b, "\x00"))
	}
	for i, c := range b[n+1:] {
		if i == 3 || c < '0' || c > '9' {
			break
		}
		status = status*10 + int(c-'0')
	}
	if status != http.StatusOK && status != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("httpdialer: failed to connect %s via %s: %s", addr, d.Host, bytes.TrimRight(b, "\x00"))
	}

	closeConn = nil
	return conn, nil
}
