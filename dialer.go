package main

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"syscall"
	"time"
)

type Dialer struct {
	Resolver  *Resolver
	Control   func(network, address string, conn syscall.RawConn) error
	LocalAddr *net.TCPAddr

	PreferIPv6    bool
	DenyIntranet  bool
	ParallelLevel int

	Timeout               time.Duration
	TCPKeepAlive          time.Duration
	TLSClientSessionCache tls.ClientSessionCache
}

func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.dialContext(context.Background(), network, address, nil)
}

func (d *Dialer) DialTLS(network, address string, tlsConfig *tls.Config) (net.Conn, error) {
	if tlsConfig.ClientSessionCache == nil {
		tlsConfig.ClientSessionCache = d.TLSClientSessionCache
	}
	return d.dialContext(context.Background(), network, address, tlsConfig)
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialContext(ctx, network, address, nil)
}

func (d *Dialer) dialContext(ctx context.Context, network, address string, tlsConfig *tls.Config) (net.Conn, error) {
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

	switch d.ParallelLevel {
	case 0, 1:
		return d.dialSerial(ctx, network, host, ips, port, tlsConfig)
	default:
		if len(ips) == 1 {
			ips = append(ips, ips[0])
		}
		return d.dialParallel(ctx, network, host, ips, port, tlsConfig)
	}
}

func (d *Dialer) dialSerial(ctx context.Context, network, hostname string, ips []net.IP, port int, tlsConfig *tls.Config) (conn net.Conn, err error) {
	for i, ip := range ips {
		if d.DenyIntranet && IsReservedIP(ip) {
			return nil, net.InvalidAddrError("intranet address is rejected: " + ip.String())
		}

		raddr := &net.TCPAddr{IP: ip, Port: port}
		conn, err = (&net.Dialer{Control: d.Control}).DialContext(ctx, network, raddr.String())
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
		err = tlsConn.Handshake()
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

func (d *Dialer) dialParallel(ctx context.Context, network, hostname string, ips []net.IP, port int, tlsConfig *tls.Config) (net.Conn, error) {
	type dialResult struct {
		Conn net.Conn
		Err  error
	}

	level := len(ips)
	if level > d.ParallelLevel {
		level = d.ParallelLevel
		ips = ips[:level]
	}

	lane := make(chan dialResult, level)
	for i := 0; i < level; i++ {
		go func(ip net.IP, port int, tlsConfig *tls.Config) {
			if d.DenyIntranet && IsReservedIP(ip) {
				lane <- dialResult{nil, net.InvalidAddrError("intranet address is rejected: " + ip.String())}
				return
			}

			raddr := &net.TCPAddr{IP: ip, Port: port}
			conn, err := (&net.Dialer{Control: d.Control}).DialContext(ctx, network, raddr.String())
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
			err = tlsConn.Handshake()

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
