package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/phuslu/log"
	"golang.org/x/net/http2"
)

var _ Dialer = (*HTTP2Dialer)(nil)

const (
	DefaultHTTP2DialerMaxClients = 8
)

type HTTP2Dialer struct {
	Username   string
	Password   string
	Host       string
	Port       string
	UserAgent  string
	CACert     string
	ClientKey  string
	ClientCert string
	MaxClients int

	Dialer Dialer

	mutexes [64]sync.Mutex
	clients [64]*http2.Transport
}

func (d *HTTP2Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	connect := func() (*http2.Transport, error) {
		return &http2.Transport{
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

				tlsConfig := &tls.Config{
					NextProtos:         []string{"h2"},
					InsecureSkipVerify: false,
					ServerName:         d.Host,
					ClientSessionCache: tls.NewLRUClientSessionCache(1024),
				}
				if d.CACert != "" && d.ClientKey != "" && d.ClientCert != "" {
					caData, err := os.ReadFile(d.CACert)
					if err != nil {
						return nil, err
					}

					cert, err := tls.LoadX509KeyPair(d.ClientCert, d.ClientKey)
					if err != nil {
						return nil, err
					}

					tlsConfig.RootCAs = x509.NewCertPool()
					tlsConfig.RootCAs.AppendCertsFromPEM(caData)
					tlsConfig.Certificates = []tls.Certificate{cert}
				}

				tlsConn := tls.Client(conn, tlsConfig)

				err = tlsConn.HandshakeContext(ctx)
				if err != nil {
					return nil, err
				}

				return tlsConn, nil
			},
		}, nil
	}

	maxClient := d.MaxClients
	if maxClient == 0 {
		maxClient = DefaultHTTP2DialerMaxClients
	}

	n := 1
	if 0 < maxClient && maxClient < len(d.clients) {
		n = maxClient
	}
	n = int(log.Fastrandn(uint32(n)))

	if d.clients[n] == nil {
		d.mutexes[n].Lock()
		c, err := connect()
		if err != nil {
			d.mutexes[n].Unlock()
			return nil, err
		}
		d.clients[n] = c
		d.mutexes[n].Unlock()
	}

	transport := d.clients[n]

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

	resp, err := transport.RoundTrip(req)
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
