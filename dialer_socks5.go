package main

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
)

type SocksVersion byte

const (
	_             SocksVersion = iota
	VersionSocks4              = 4
	VersionSocks5              = 5
)

type SocksCommand byte

const (
	_                   SocksVersion = iota
	SocksCommandConnect              = 1
)

type Socks4Status byte

const (
	_                               Socks4Status = iota
	Socks4StatusRequestGranted                   = 0x5a
	Socks4StatusConnectionForbidden              = 0x5b
	Socks4StatusIdentdRequired                   = 0x5c
	Socks4StatusIdentdFailed                     = 0x5d
)

func (s Socks4Status) String() string {
	switch s {
	case Socks4StatusRequestGranted:
		return "request granted"
	case Socks4StatusConnectionForbidden:
		return "connection forbidden"
	case Socks4StatusIdentdRequired:
		return "identd required"
	case Socks4StatusIdentdFailed:
		return "identd failed"
	}
	return "socks4 status: errno 0x" + strconv.FormatInt(int64(s), 16)
}

type Socks5AddressType byte

const (
	_                 Socks5AddressType = iota
	Socks5IPv4Address                   = 1
	Socks5DomainName                    = 3
	Socks5IPv6Address                   = 4
)

const (
	Socks5AuthMethodNone     byte = 0
	Socks5AuthMethodGSSAPI   byte = 1
	Socks5AuthMethodPassword byte = 2
)

type Socks5Status byte

const (
	Socks5StatusRequestGranted Socks5Status = iota
	Socks5StatusGeneralFailure
	Socks5StatusConnectionNotAllowedByRuleset
	Socks5StatusNetworkUnreachable
	Socks5StatusHostUnreachable
	Socks5StatusConnectionRefusedByDestinationHost
	Socks5StatusTTLExpired
	Socks5StatusCommandNotSupported
	Socks5StatusAddressTypeNotSupported
)

func (s Socks5Status) String() string {
	switch s {
	case Socks5StatusRequestGranted:
		return "request granted"
	case Socks5StatusGeneralFailure:
		return "general failure"
	case Socks5StatusConnectionNotAllowedByRuleset:
		return "connection not allowed by ruleset"
	case Socks5StatusNetworkUnreachable:
		return "network unreachable"
	case Socks5StatusHostUnreachable:
		return "host unreachable"
	case Socks5StatusConnectionRefusedByDestinationHost:
		return "connection refused by destination host"
	case Socks5StatusTTLExpired:
		return "TTL expired"
	case Socks5StatusCommandNotSupported:
		return "command not supported"
	case Socks5StatusAddressTypeNotSupported:
		return "address type not supported"
	}
	return "socks5 status: errno 0x" + strconv.FormatInt(int64(s), 16)
}

type Socks5Dialer struct {
	Username string
	Password string
	Host     string
	Port     string
	Socsk5H  bool
	Dialer   *Dialer
}

func (d *Socks5Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, errors.New("proxy: no support for SOCKS5 proxy connections of type " + network)
	}

	conn, err := d.Dialer.DialContext(ctx, network, net.JoinHostPort(d.Host, d.Port))
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

	if !d.Socsk5H && d.Dialer.Resolver != nil {
		hosts, err := d.Dialer.Resolver.LookupHost(ctx, host)
		if err == nil && len(hosts) > 0 {
			host = hosts[0]
		}
	}

	// the size here is just an estimate
	buf := make([]byte, 0, 6+len(host))

	buf = append(buf, VersionSocks5)
	if len(d.Username) > 0 && len(d.Username) < 256 && len(d.Password) < 256 {
		buf = append(buf, 2 /* num auth methods */, Socks5AuthMethodNone, Socks5AuthMethodPassword)
	} else {
		buf = append(buf, 1 /* num auth methods */, Socks5AuthMethodNone)
	}

	if _, err := conn.Write(buf); err != nil {
		return nil, errors.New("proxy: failed to write greeting to SOCKS5 proxy at " + d.Host + ": " + err.Error())
	}

	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return nil, errors.New("proxy: failed to read greeting from SOCKS5 proxy at " + d.Host + ": " + err.Error())
	}
	if buf[0] != 5 {
		return nil, errors.New("proxy: SOCKS5 proxy at " + d.Host + " has unexpected version " + strconv.Itoa(int(buf[0])))
	}
	if buf[1] == 0xff {
		return nil, errors.New("proxy: SOCKS5 proxy at " + d.Host + " requires authentication")
	}

	if buf[1] == byte(Socks5AuthMethodPassword) {
		buf = buf[:0]
		buf = append(buf, 1 /* password protocol version */)
		buf = append(buf, uint8(len(d.Username)))
		buf = append(buf, d.Username...)
		buf = append(buf, uint8(len(d.Password)))
		buf = append(buf, d.Password...)

		if _, err := conn.Write(buf); err != nil {
			return nil, errors.New("proxy: failed to write authentication request to SOCKS5 proxy at " + d.Host + ": " + err.Error())
		}

		if _, err := io.ReadFull(conn, buf[:2]); err != nil {
			return nil, errors.New("proxy: failed to read authentication reply from SOCKS5 proxy at " + d.Host + ": " + err.Error())
		}

		if buf[1] != 0 {
			return nil, errors.New("proxy: SOCKS5 proxy at " + d.Host + " rejected username/password")
		}
	}

	buf = buf[:0]
	buf = append(buf, VersionSocks5, SocksCommandConnect, 0 /* reserved */)

	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf = append(buf, Socks5IPv4Address)
			ip = ip4
		} else {
			buf = append(buf, Socks5IPv6Address)
		}
		buf = append(buf, ip...)
	} else {
		if len(host) > 255 {
			return nil, errors.New("proxy: destination hostname too long: " + host)
		}
		buf = append(buf, Socks5DomainName)
		buf = append(buf, byte(len(host)))
		buf = append(buf, host...)
	}
	buf = append(buf, byte(port>>8), byte(port))

	if _, err := conn.Write(buf); err != nil {
		return nil, errors.New("proxy: failed to write connect request to SOCKS5 proxy at " + d.Host + ": " + err.Error())
	}

	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return nil, errors.New("proxy: failed to read connect reply from SOCKS5 proxy at " + d.Host + ": " + err.Error())
	}

	if status := Socks5Status(buf[1]); status > 0 {
		return nil, errors.New("proxy: SOCKS5 proxy at " + d.Host + " failed to connect: " + status.String())
	}

	bytesToDiscard := 0
	switch buf[3] {
	case Socks5IPv4Address:
		bytesToDiscard = net.IPv4len
	case Socks5IPv6Address:
		bytesToDiscard = net.IPv6len
	case Socks5DomainName:
		_, err := io.ReadFull(conn, buf[:1])
		if err != nil {
			return nil, errors.New("proxy: failed to read domain length from SOCKS5 proxy at " + d.Host + ": " + err.Error())
		}
		bytesToDiscard = int(buf[0])
	default:
		return nil, errors.New("proxy: got unknown address type " + strconv.Itoa(int(buf[3])) + " from SOCKS5 proxy at " + d.Host)
	}

	if cap(buf) < bytesToDiscard {
		buf = make([]byte, bytesToDiscard)
	} else {
		buf = buf[:bytesToDiscard]
	}
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, errors.New("proxy: failed to read address from SOCKS5 proxy at " + d.Host + ": " + err.Error())
	}

	// Also need to discard the port number
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return nil, errors.New("proxy: failed to read port from SOCKS5 proxy at " + d.Host + ": " + err.Error())
	}

	closeConn = nil
	return conn, nil
}
