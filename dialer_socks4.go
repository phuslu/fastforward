package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
)

type Socks4Dialer struct {
	Username string
	Password string
	Host     string
	Port     string
	Socks4A  bool
	Dialer   *Dialer
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

	if d.Dialer.Resolver != nil {
		if hosts, err := d.Dialer.Resolver.LookupHost(ctx, host); err == nil && len(hosts) > 0 {
			host = hosts[0]
		}
	}

	buf := make([]byte, 0, 1024)

	buf = append(buf, VersionSocks4, SocksCommandConnect)
	buf = append(buf, byte(port>>8), byte(port))
	if d.Socks4A {
		buf = append(buf, 0, 0, 0, 1, 0)
		buf = append(buf, []byte(host+"\x00")...)
	} else {
		ip, err := net.ResolveIPAddr("ip4", host)
		if err != nil {
			return nil, err
		}
		ip4 := ip.IP.To4()
		if len(ip4) < 4 {
			return nil, errors.New("proxy: resolve ip address out of range: " + ip.String())
		}
		buf = append(buf, ip4[0], ip4[1], ip4[2], ip4[3], 0)
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
