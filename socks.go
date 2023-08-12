package main

import (
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
	_                      SocksCommand = iota
	SocksCommandConnectTCP              = 1
	SocksCommandConnectUDP              = 3
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
