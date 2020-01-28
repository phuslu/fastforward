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
	"github.com/phuslu/quic-go"
	"github.com/phuslu/quic-go/http3"
)

const nextProtoH3 = "h3-24"

type HTTP3Dialer struct {
	Username  string
	Password  string
	Host      string
	Port      string
	UserAgent string

	once         sync.Once
	roundTripper *http3.RoundTripper
}

func (d *HTTP3Dialer) init() {
	if d.UserAgent == "" {
		d.UserAgent = DefaultHTTPDialerUserAgent
	}

	d.roundTripper = &http3.RoundTripper{
		DisableCompression: false,
		Dial: func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.Session, error) {
			tlsConfig := &tls.Config{
				NextProtos:         []string{nextProtoH3},
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: true,
			}
			quicConfig := &quic.Config{
				MaxIncomingStreams: -1,
				MaxIdleTimeout:     300 * time.Second,
				KeepAlive:          true,
			}

			log.Info().Msgf("addr=%#v, tlsConfig=%#v, quicConfig=%#v", addr, tlsConfig, quicConfig)

			return quic.DialAddr(net.JoinHostPort(d.Host, d.Port), tlsConfig, quicConfig)
		},
	}
}

func (d *HTTP3Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.once.Do(d.init)

	pr, pw := io.Pipe()
	req := &http.Request{
		Proto:      "HTTP/3",
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

	log.Info().Msgf("http3 RoundTrip req=%#v", req)

	resp, err := d.roundTripper.RoundTrip(req)
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

	log.Info().Msgf("resp=%#v, resp.Body=%#v", resp, resp.Body)

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
