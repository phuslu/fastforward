package main

import (
	"net"

	"github.com/phuslu/log"
)

type DNSRequest struct {
	RemoteAddr string
	RemoteIP   string
	ServerAddr string
}

type DNSHandler struct {
	Config      DNSConfig
	DNSLogger   log.Logger
	LocalDialer *LocalDialer
}

func (h *DNSHandler) Load() error {
	return nil
}

func (h *DNSHandler) ServePacketConn(conn net.PacketConn, addr net.Addr, buf []byte) {
	return
}
