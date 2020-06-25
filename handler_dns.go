package main

import (
	"net"

	"github.com/phuslu/log"
	"golang.org/x/net/dns/dnsmessage"
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
	var p dnsmessage.Parser

	header, err := p.Start(buf)
	if err != nil {
		log.Error().Err(err).Stringer("remote_ip", addr).Msg("parse dns message header error")
	}

	questions, err := p.AllQuestions()
	if err != nil || len(questions) == 0 {
		log.Error().Err(err).Stringer("remote_ip", addr).Msg("parse dns message questions error")
	}
	question := questions[0]

	log.Info().Stringer("remote_ip", addr).Str("dns_header", header.GoString()).Str("dns_question", question.GoString()).Msg("parse dns message ok")
	return
}
