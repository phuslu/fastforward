package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"
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
)

var _ Dialer = (*LocalDialer)(nil)

type LocalDialer struct {
	Resolver *Resolver

	Interface       string
	PreferIPv6      bool
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

	ips, err := d.Resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	switch len(ips) {
	case 0:
		return nil, net.InvalidAddrError("invaid dns record: " + address)
	case 1:
		break
	default:
		slices.SortFunc(ips, func(a, b netip.Addr) int {
			switch {
			case a.Is6() && b.Is4():
				if d.PreferIPv6 {
					return -1
				} else {
					return 1
				}
			case a.Is4() && b.Is6():
				if d.PreferIPv6 {
					return 1
				} else {
					return -1
				}
			default:
				return 0
			}
		})
		if d.PreferIPv6 {
			if i := slices.IndexFunc(ips, func(a netip.Addr) bool { return a.Is4() }); i > 0 {
				ips = ips[:i]
			}
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

	switch d.Concurrency {
	case 0, 1:
		return d.dialSerial(ctx, network, host, ips, uint16(port), tlsConfig)
	default:
		if len(ips) == 1 {
			ips = append(ips, ips[0])
		}
		return d.dialParallel(ctx, network, host, ips, uint16(port), tlsConfig)
	}
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
