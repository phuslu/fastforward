package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/phuslu/log"
	"github.com/phuslu/lru"
)

type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type DialerContextKey struct {
	name string
}

func (k *DialerContextKey) String() string { return "dialer context value " + k.name }

var (
	DialerHTTPHeaderContextKey = &DialerContextKey{"dailer-http-header"}
	DialerPreferIPv6ContextKey = &DialerContextKey{"dailer-prefer-ipv6"}
)

var _ Dialer = (*LocalDialer)(nil)

type LocalDialer struct {
	Resolver     *Resolver
	ResolveCache *lru.TTLCache[string, []netip.Addr]

	Interface       string
	PerferIPv6      bool
	ForbidLocalAddr bool
	Concurrency     int

	DialTimeout   time.Duration
	TCPKeepAlive  time.Duration
	ReadBuffSize  int
	WriteBuffSize int
	TLSConfig     *tls.Config
}

func (d *LocalDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialContext(ctx, network, address, nil)
}

func (d *LocalDialer) DialTLSContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.TLSConfig == nil {
		return nil, errors.New("localdialer: empty tls config")
	}
	return d.dialContext(ctx, network, address, d.TLSConfig)
}

func (d *LocalDialer) dialContext(ctx context.Context, network, address string, tlsConfig *tls.Config) (net.Conn, error) {
	switch network {
	case "tcp", "tcp6", "tcp4":
		break
	default:
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	ips, _ := d.ResolveCache.Get(host)
	if len(ips) == 0 {
		ips, err = d.Resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	if len(ips) == 0 {
		return nil, net.InvalidAddrError("empty dns record: " + host)
	}

	var ipv6only []netip.Addr
	if i := slices.IndexFunc(ips, func(a netip.Addr) bool { return a.Is6() }); i > 0 {
		if d.PerferIPv6 || ctx.Value(DialerPreferIPv6ContextKey) != nil {
			ips = ips[i:]
			ipv6only = ips[:len(ips)-i]
		} else {
			ips = ips[:len(ips)-i]
		}
	}

	port, _ := strconv.Atoi(portStr)

	if d.DialTimeout > 0 {
		deadline := timeNow().Add(d.DialTimeout)
		if d, ok := ctx.Deadline(); ok && deadline.After(d) {
			deadline = d
		}

		subCtx, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		ctx = subCtx
	}

	concurrency := max(d.Concurrency, 1)
	dial := d.dialParallel
	if concurrency <= 1 || len(ipv6only) == 1 || len(ips) == 1 {
		dial = d.dialSerial
	}

	conn, err := dial(ctx, network, host, ips, uint16(port), tlsConfig)
	if err != nil && strings.Contains(err.Error(), "connect: network is unreachable") && len(ips) > concurrency {
		news := ips[len(ips)-concurrency:]
		log.Warn().Err(err).Str("network", network).Str("host", host).Interface("ips", ips).Interface("new_ips", news).Msg("retry dialing")
		conn, err = dial(ctx, network, host, news, uint16(port), tlsConfig)
		if err == nil {
			d.ResolveCache.Set(host, news, d.Resolver.CacheDuration)
		}
	}
	return conn, err
}

func (d *LocalDialer) dialSerial(ctx context.Context, network, hostname string, ips []netip.Addr, port uint16, tlsConfig *tls.Config) (conn net.Conn, err error) {
	for i, ip := range ips {
		if d.ForbidLocalAddr && (ip.IsLoopback() || ip.IsPrivate()) {
			return nil, net.InvalidAddrError("intranet address is rejected: " + ip.String())
		}

		dailer := &net.Dialer{}
		if d.Interface != "" {
			dailer.Control = (&DailerController{Interface: d.Interface}).Control
		}
		conn, err = dailer.DialContext(ctx, network, netip.AddrPortFrom(ip, port).String())
		if err != nil {
			if i < len(ips)-1 {
				continue
			} else {
				return nil, err
			}
		}

		if tlsConfig == nil {
			return conn, nil
		}

		tlsConn := tls.Client(conn, tlsConfig)
		err = tlsConn.HandshakeContext(ctx)
		if err != nil {
			if i < len(ips)-1 {
				continue
			} else {
				return nil, err
			}
		}

		return tlsConn, nil
	}
	return nil, err
}

func (d *LocalDialer) dialParallel(ctx context.Context, network, hostname string, ips []netip.Addr, port uint16, tlsConfig *tls.Config) (net.Conn, error) {
	type dialResult struct {
		Conn net.Conn
		Err  error
	}

	level := len(ips)
	if level > d.Concurrency {
		level = d.Concurrency
		ips = ips[:level]
	}

	lane := make(chan dialResult, level)
	for i := 0; i < level; i++ {
		go func(ip netip.Addr, port uint16, tlsConfig *tls.Config) {
			if d.ForbidLocalAddr && (ip.IsLoopback() || ip.IsPrivate()) {
				lane <- dialResult{nil, net.InvalidAddrError("intranet address is rejected: " + ip.String())}
				return
			}

			dailer := &net.Dialer{}
			if d.Interface != "" {
				dailer.Control = (&DailerController{Interface: d.Interface}).Control
			}
			conn, err := dailer.DialContext(ctx, network, netip.AddrPortFrom(ip, port).String())
			if err != nil {
				lane <- dialResult{nil, err}
				return
			}

			if d.TCPKeepAlive > 0 {
				if tc, ok := conn.(*net.TCPConn); ok {
					tc.SetKeepAlive(true)
					tc.SetKeepAlivePeriod(d.TCPKeepAlive)
				}
			}

			if d.ReadBuffSize > 0 {
				if tc, ok := conn.(*net.TCPConn); ok {
					tc.SetReadBuffer(d.ReadBuffSize)
				}
			}

			if d.WriteBuffSize > 0 {
				if tc, ok := conn.(*net.TCPConn); ok {
					tc.SetReadBuffer(d.WriteBuffSize)
				}
			}

			if tlsConfig == nil {
				lane <- dialResult{conn, nil}
				return
			}

			tlsConn := tls.Client(conn, tlsConfig)
			err = tlsConn.HandshakeContext(ctx)

			if err != nil {
				lane <- dialResult{nil, err}
				return
			}

			lane <- dialResult{tlsConn, nil}
		}(ips[i], port, tlsConfig)
	}

	var r dialResult
	for j := 0; j < level; j++ {
		r = <-lane
		if r.Err == nil {
			go func(count int) {
				var r1 dialResult
				for ; count > 0; count-- {
					r1 = <-lane
					if r1.Conn != nil {
						r1.Conn.Close()
					}
				}
			}(level - 1 - j)
			return r.Conn, nil
		}
	}

	return nil, r.Err
}
