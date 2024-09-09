package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/apernet/quic-go"
	"github.com/apernet/quic-go/http3"
	"github.com/phuslu/log"
	"github.com/smallnest/ringbuffer"
)

var _ Dialer = (*HTTP3Dialer)(nil)

type HTTP3Dialer struct {
	Username  string
	Password  string
	Host      string
	Port      string
	UserAgent string
	Websocket bool
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

	if d.transport != nil {
		return
	}

	d.transport = &http3.RoundTripper{
		DisableCompression: false,
		EnableDatagrams:    false,
		Dial: func(ctx context.Context, addr string, tlsConf *tls.Config, conf *quic.Config) (quic.EarlyConnection, error) {
			host := d.Host
			if d.Resolver != nil {
				if ips, err := d.Resolver.LookupNetIP(ctx, "ip", host); err == nil && len(ips) != 0 {
					// host = ips[fastrandn(uint32(len(ips)))].String()
					host = ips[0].String()
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
					DisablePathMTUDiscovery: false,
					EnableDatagrams:         false,
					MaxIncomingUniStreams:   200,
					MaxIncomingStreams:      200,
					// MaxStreamReceiveWindow:     6 * 1024 * 1024,
					// MaxConnectionReceiveWindow: 15 * 1024 * 1024,
				},
			)
		},
	}

	if d.UserAgent == "" {
		d.UserAgent = DefaultUserAgent
	}
}

func (d *HTTP3Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	d.init()

	pr, pw := ringbuffer.New(8192).Pipe()
	req := &http.Request{
		ProtoMajor: 3,
		Method:     http.MethodConnect,
		URL: &url.URL{
			Scheme: "https",
			Host:   addr,
		},
		Host: addr,
		Header: http.Header{
			"content-type":        []string{"application/octet-stream"},
			"user-agent":          []string{d.UserAgent},
			"x-forwarded-network": []string{network},
		},
		Body:          pr,
		ContentLength: -1,
	}
	if header, _ := ctx.Value(DialerHTTPHeaderContextKey).(http.Header); header != nil {
		log.Debug().Any("dialer_http_header", header).Msg("http3 dialer set extras headers")
		for key, values := range header {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}

	if d.Username != "" && d.Password != "" {
		req.Header.Set("proxy-authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(d.Username+":"+d.Password)))
	}

	if d.Websocket {
		// see https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-connect-tcp-05
		key := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%x%x\n", fastrandn(1<<32-1), fastrandn(1<<32-1))))
		i := strings.LastIndexByte(addr, ':')
		req.URL.Path = fmt.Sprintf("/.well-known/masque/tcp/%s/%s/", addr[:i], addr[i+1:])
		req.URL.Host = d.Host
		req.Host = d.Host
		req.Method = http.MethodGet
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		req.Header.Set("Sec-WebSocket-Version", "13")
		req.Header.Set("Sec-WebSocket-Key", key)
		log.Debug().Stringer("req_url", req.URL).Any("req_header", req.Header).Msg("http3dialer websocket request")
	}

	var remoteAddr, localAddr net.Addr

	req = req.WithContext(httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr, localAddr = connInfo.Conn.RemoteAddr(), connInfo.Conn.LocalAddr()
		},
	}))

	resp, err := d.transport.RoundTripOpt(req, http3.RoundTripOpt{OnlyCachedConn: false})
	if err != nil {
		if strings.Contains(err.Error(), "timeout: ") {
			log.Warn().Err(err).Msg("close underlying http3 connection")
			d.transport.Close()
		}
		return nil, err
	}

	log.Debug().Int("resp_statuscode", resp.StatusCode).Any("resp_header", resp.Header).Msg("http3dialer websocket response")

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSwitchingProtocols {
		data, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return nil, errors.New("proxy: read from " + d.Host + " error: " + resp.Status + ": " + string(data))
	}

	if remoteAddr == nil || localAddr == nil {
		remoteAddr, localAddr = &net.UDPAddr{}, &net.UDPAddr{}
	}

	return &http3Stream{
		r:          resp.Body,
		w:          pw,
		closed:     make(chan struct{}),
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}, nil
}

type http3Stream struct {
	r io.ReadCloser
	w io.Writer

	closed chan struct{}

	remoteAddr net.Addr
	localAddr  net.Addr
}

func (c *http3Stream) Read(b []byte) (n int, err error) {
	return c.r.Read(b)
}

func (c *http3Stream) Write(b []byte) (n int, err error) {
	return c.w.Write(b)
}

func (c *http3Stream) Close() (err error) {
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

func (c *http3Stream) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *http3Stream) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *http3Stream) SetDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http3", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http3Stream) SetReadDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http3", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}

func (c *http3Stream) SetWriteDeadline(t time.Time) error {
	return &net.OpError{Op: "set", Net: "http3", Source: nil, Addr: nil, Err: errors.New("deadline not supported")}
}
