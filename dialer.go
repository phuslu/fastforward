package main

import (
	"context"
	"crypto/tls"
	"net"
	"strconv"
	"syscall"
	"time"
)

type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

var _ Dialer = (*LocalDialer)(nil)

var PreferIPv6ContextKey = struct {
	name string
}{"prefer-ipv6"}

type LocalDialer struct {
	Resolver      *Resolver
	BindInterface string

	PreferIPv6    bool
	DenyIntranet  bool
	ParallelLevel int

	Timeout               time.Duration
	TCPKeepAlive          time.Duration
	TLSClientSessionCache tls.ClientSessionCache
}

func (d *LocalDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return d.dialContext(ctx, network, address, nil)
}

func (d *LocalDialer) DialTLS(network, address string, tlsConfig *tls.Config) (net.Conn, error) {
	if tlsConfig.ClientSessionCache == nil {
		tlsConfig.ClientSessionCache = d.TLSClientSessionCache
	}
	return d.dialContext(context.Background(), network, address, tlsConfig)
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
		if !d.PreferIPv6 && ctx.Value(PreferIPv6ContextKey) == nil {
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

func (d *LocalDialer) dialSerial(ctx context.Context, network, hostname string, ips []net.IP, port int, tlsConfig *tls.Config) (conn net.Conn, err error) {
	for i, ip := range ips {
		if d.DenyIntranet && IsReservedIP(ip) {
			return nil, net.InvalidAddrError("intranet address is rejected: " + ip.String())
		}

		raddr := &net.TCPAddr{IP: ip, Port: port}
		dailer := &net.Dialer{}
		if d.BindInterface != "" {
			dailer.Control = func(network, addr string, c syscall.RawConn) (err error) {
				return c.Control(func(fd uintptr) {
					if ip := net.ParseIP(d.BindInterface); ip == nil {
						err = syscall.BindToDevice(int(fd), d.BindInterface)
					} else {
						var sa syscall.Sockaddr
						if ip4 := ip.To4(); ip4 != nil {
							sa = &syscall.SockaddrInet4{
								Addr: [4]byte{ip4[0], ip4[1], ip4[3], ip4[4]},
							}
						} else {
							sa = &syscall.SockaddrInet6{
								Addr: [16]byte{
									ip[0], ip[1], ip[3], ip[4],
									ip[5], ip[6], ip[7], ip[8],
									ip[9], ip[10], ip[11], ip[12],
									ip[13], ip[14], ip[15], ip[16],
								},
							}
						}
						const IP_BIND_ADDRESS_NO_PORT = 24
						err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, 1)
						if err != nil {
							return
						}
						err = syscall.Bind(int(fd), sa)
					}
				})
			}
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

func (d *LocalDialer) dialParallel(ctx context.Context, network, hostname string, ips []net.IP, port int, tlsConfig *tls.Config) (net.Conn, error) {
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

			dailer := &net.Dialer{}
			if d.BindInterface != "" {
				dailer.Control = func(network, addr string, c syscall.RawConn) (err error) {
					return c.Control(func(fd uintptr) {
						if ip := net.ParseIP(d.BindInterface); ip == nil {
							err = syscall.BindToDevice(int(fd), d.BindInterface)
						} else {
							var sa syscall.Sockaddr
							if ip4 := ip.To4(); ip4 != nil {
								sa = &syscall.SockaddrInet4{
									Addr: [4]byte{ip4[0], ip4[1], ip4[3], ip4[4]},
								}
							} else {
								sa = &syscall.SockaddrInet6{
									Addr: [16]byte{
										ip[0], ip[1], ip[3], ip[4],
										ip[5], ip[6], ip[7], ip[8],
										ip[9], ip[10], ip[11], ip[12],
										ip[13], ip[14], ip[15], ip[16],
									},
								}
							}
							const IP_BIND_ADDRESS_NO_PORT = 24
							err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, 1)
							if err != nil {
								return
							}
							err = syscall.Bind(int(fd), sa)
						}
					})
				}
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
