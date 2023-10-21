package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

var _ Dialer = (*Socks4Dialer)(nil)

type Socks4Dialer struct {
	Username string
	Password string
	Host     string
	Port     string
	Socks4A  bool
	Resolver *Resolver
	Dialer   Dialer
}

func (d *Socks4Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, errors.New("proxy: no support for SOCKS4 proxy connections of type " + network)
	}

	conn, err := d.Dialer.DialContext(ctx, "tcp", net.JoinHostPort(d.Host, d.Port))
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

	if d.Resolver != nil {
		if hosts, err := d.Resolver.LookupHost(ctx, host); err == nil && len(hosts) > 0 {
			host = hosts[0]
		}
	}

	buf := make([]byte, 0, 1024)

	switch network {
	case "tcp", "tcp6", "tcp4":
		buf = append(buf, VersionSocks4, SocksCommandConnectTCP)
	case "udp", "udp6", "udp4":
		buf = append(buf, VersionSocks4, SocksCommandConnectUDP)
	default:
		return nil, errors.New("proxy: no support for SOCKS5 proxy connections of type " + network)
	}

	buf = append(buf, byte(port>>8), byte(port))
	if d.Socks4A {
		buf = append(buf, 0, 0, 0, 1, 0)
		buf = append(buf, []byte(host+"\x00")...)
	} else {
		ips, err := d.Resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("proxy: resolve %s return empty ip list", host)
		}
		if !ips[0].Is4() {
			return nil, errors.New("proxy: resolve ip address out of range: " + ips[0].String())
		}
		ip4 := ips[0].As4()
		buf = append(buf, ip4[0], ip4[1], ip4[2], ip4[3], 0)
	}

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}

	_, err = conn.Write(buf)
	if err != nil {
		return nil, err
	}

	var resp [8]byte
	_, err = conn.Read(resp[:])
	if err != nil && err != io.EOF {
		return nil, err
	}

	if status := Socks4Status(resp[1]); status > 0 {
		return nil, errors.New("proxy: SOCKS4 proxy at " + d.Host + " failed to connect: " + status.String())
	}

	closeConn = nil
	return conn, nil
}
