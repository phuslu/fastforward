package main

import (
	"crypto/tls"
	"strconv"
)

const (
	DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36"
)

type TLSVersion uint16

var (
	TLSVersion13 TLSVersion = tls.VersionTLS13
	TLSVersion12 TLSVersion = tls.VersionTLS12
	TLSVersion11 TLSVersion = tls.VersionTLS11
	TLSVersion10 TLSVersion = tls.VersionTLS10
)

func (v TLSVersion) String() string {
	switch v {
	case TLSVersion13:
		return "TLSv1.3"
	case TLSVersion12:
		return "TLSv1.2"
	case TLSVersion11:
		return "TLSv1.1"
	case TLSVersion10:
		return "TLSv1.0"
	}
	return ""
}

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
