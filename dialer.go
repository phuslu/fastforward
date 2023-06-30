package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"time"
)

type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

var _ Dialer = (*LocalDialer)(nil)

var PreferIPv6ContextKey = struct {
	name string
}{"prefer-ipv6"}

var BindInterfaceContextKey = struct {
	name string
}{"bind-interface"}

type LocalDialer struct {
	Resolver *Resolver

	BindInterface string
	PreferIPv6    bool
	DenyLocalLAN  bool
	Concurrency   int

	Timeout      time.Duration
	TCPKeepAlive time.Duration
	TLSConfig    *tls.Config
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

	ips, err := d.Resolver.LookupIP(ctx, host)
	if err != nil {
		return nil, err
	}

	switch len(ips) {
	case 0:
		return nil, net.InvalidAddrError("invaid dns record: " + address)
	case 1:
		break
	default:
		if !d.PreferIPv6 {
			if ips[0].To4() == nil {
				pos := len(ips) - 1
				if ips[pos].To4() != nil {
					ips[0], ips[pos] = ips[pos], ips[0]
				}
			}
		} else {
			if ips[0].To4() != nil {
				pos := len(ips) - 1
				if ips[pos].To4() == nil {
					ips[0], ips[pos] = ips[pos], ips[0]
				}
			}
		}
	}

	port, _ := strconv.Atoi(portStr)

	if d.Timeout > 0 {
		deadline := timeNow().Add(d.Timeout)
		if d, ok := ctx.Deadline(); ok && deadline.After(d) {
			deadline = d
		}

		subCtx, cancel := context.WithDeadline(ctx, deadline)
		defer cancel()
		ctx = subCtx
	}

	switch d.Concurrency {
	case 0, 1:
		return d.dialSerial(ctx, network, host, ips, port, tlsConfig)
	default:
		if len(ips) == 1 {
			ips = append(ips, ips[0])
		}
		return d.dialParallel(ctx, network, host, ips, port, tlsConfig)
	}
}

func (d *LocalDialer) dialSerial(ctx context.Context, network, hostname string, ips []net.IP, port int, tlsConfig *tls.Config) (conn net.Conn, err error) {
	for i, ip := range ips {
		if d.DenyLocalLAN && IsReservedIP(ip) {
			return nil, net.InvalidAddrError("intranet address is rejected: " + ip.String())
		}

		raddr := &net.TCPAddr{IP: ip, Port: port}
		dailer := &net.Dialer{}
		if d.BindInterface != "" {
			dailer.Control = (&DailerController{BindInterface: d.BindInterface}).Control
		}
		conn, err = dailer.DialContext(ctx, network, raddr.String())
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

func (d *LocalDialer) dialParallel(ctx context.Context, network, hostname string, ips []net.IP, port int, tlsConfig *tls.Config) (net.Conn, error) {
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
		go func(ip net.IP, port int, tlsConfig *tls.Config) {
			if d.DenyLocalLAN && IsReservedIP(ip) {
				lane <- dialResult{nil, net.InvalidAddrError("intranet address is rejected: " + ip.String())}
				return
			}

			dailer := &net.Dialer{}
			if d.BindInterface != "" {
				dailer.Control = (&DailerController{BindInterface: d.BindInterface}).Control
			}
			raddr := &net.TCPAddr{IP: ip, Port: port}
			conn, err := dailer.DialContext(ctx, network, raddr.String())
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
