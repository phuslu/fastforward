package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/phuslu/log"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
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

	Resolvers []*Resolver
}

func (h *DNSHandler) Load() error {
	for _, dnsServer := range h.Config.Upstream {
		if !strings.Contains(dnsServer, "://") {
			dnsServer = "udp://" + dnsServer
		}
		u, err := url.Parse(dnsServer)
		if err != nil {
			log.Fatal().Err(err).Str("dns_server", dnsServer).Msg("parse dns_server error")
		}
		if u.Scheme == "" || u.Host == "" {
			log.Fatal().Err(errors.New("no scheme or host")).Str("dns_server", dnsServer).Msg("parse dns_server error")
		}

		resolver := &Resolver{
			Resolver: &net.Resolver{
				PreferGo: false,
			},
			DNSCacheTTL: 10 * time.Minute,
		}

		switch u.Scheme {
		case "udp", "tcp":
			var addr = u.Host
			if _, _, err := net.SplitHostPort(u.Host); err != nil {
				addr = net.JoinHostPort(addr, "53")
			}
			resolver.Resolver.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, u.Scheme, addr)
			}
		case "tls":
			var addr = u.Host
			if _, _, err := net.SplitHostPort(u.Host); err != nil {
				addr = net.JoinHostPort(addr, "853")
			}
			tlsConfig := &tls.Config{
				ServerName:         u.Hostname(),
				ClientSessionCache: tls.NewLRUClientSessionCache(128),
			}
			resolver.Resolver.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
				return tls.Dial("tcp", addr, tlsConfig)
			}
		case "https":
			resolver.Resolver.Dial = (&DoHDialer{
				EndPoint:  dnsServer,
				UserAgent: DefaultHTTPDialerUserAgent,
				Transport: &http2.Transport{
					TLSClientConfig: &tls.Config{
						ServerName:         u.Hostname(),
						ClientSessionCache: tls.NewLRUClientSessionCache(128),
					},
				},
			}).DialContext
		}

		h.Resolvers = append(h.Resolvers, resolver)
	}
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
