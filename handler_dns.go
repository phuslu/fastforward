package main

import (
	"context"
	"net"
	"text/template"

	"github.com/phuslu/fastdns"
	"github.com/phuslu/log"
)

type DnsRequest struct {
	RemoteAddr string
	RemoteIP   string
	ServerAddr string
	Message    *fastdns.Message
	TraceID    log.XID
}

type DnsHandler struct {
	Config    DnsConfig
	Logger    log.Logger
	Functions template.FuncMap

	policy *template.Template
	dialer *template.Template
}

func (h *DnsHandler) Load() error {
	return nil
}

func (h *DnsHandler) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	var req DnsRequest
	req.RemoteAddr = conn.RemoteAddr().String()
	req.RemoteIP, _, _ = net.SplitHostPort(req.RemoteAddr)
	req.ServerAddr = conn.LocalAddr().String()
	req.Message = fastdns.AcquireMessage()
	req.TraceID = log.NewXID()

	for {
		_, err := conn.Read(req.Message.Raw)
		if err != nil {
			continue
		}
		err = fastdns.ParseMessage(req.Message, req.Message.Raw, false)
		if err != nil {
			continue
		}
	}
}
