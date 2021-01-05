package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/phuslu/log"
	"github.com/tidwall/shardmap"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/http2"
)

type DNSHandler struct {
	Config    DNSConfig
	DNSLogger log.Logger

	resolvers []*net.Resolver
	cache     *shardmap.Map
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

		var dail func(ctx context.Context, network, address string) (net.Conn, error)
		switch u.Scheme {
		case "udp", "tcp":
			var addr = u.Host
			if _, _, err := net.SplitHostPort(u.Host); err != nil {
				addr = net.JoinHostPort(addr, "53")
			}
			dail = func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, u.Scheme, addr)
			}
		case "tls", "dot":
			var addr = u.Host
			if _, _, err := net.SplitHostPort(u.Host); err != nil {
				addr = net.JoinHostPort(addr, "853")
			}
			tlsConfig := &tls.Config{
				ServerName:         u.Hostname(),
				ClientSessionCache: tls.NewLRUClientSessionCache(128),
			}
			dail = func(ctx context.Context, _, _ string) (net.Conn, error) {
				return tls.Dial("tcp", addr, tlsConfig)
			}
		case "https", "doh":
			dail = (&DoHDialer{
				EndPoint:  dnsServer,
				UserAgent: DefaultUserAgent,
				Transport: &http2.Transport{
					TLSClientConfig: &tls.Config{
						ServerName:         u.Hostname(),
						ClientSessionCache: tls.NewLRUClientSessionCache(128),
					},
				},
			}).DialContext
		}

		h.resolvers = append(h.resolvers, &net.Resolver{
			PreferGo: true,
			Dial:     dail,
		})
	}
	if len(h.resolvers) == 0 {
		h.resolvers = []*net.Resolver{
			{PreferGo: true},
		}
	}
	h.cache = shardmap.New(0)
	return nil
}

func (h *DNSHandler) ServePacketConn(conn net.PacketConn, addr net.Addr, buf []byte) {
	var msg dnsmessage.Message

	err := msg.Unpack(buf)
	if err != nil {
		log.Error().Err(err).Stringer("remote_ip", addr).Hex("buf", buf).Msg("parse dns message header error")
	}
	if len(msg.Questions) != 1 {
		log.Error().Err(err).Stringer("remote_ip", addr).Str("msg_header", msg.Header.GoString()).Interface("msg_questions", msg.Questions[0]).Msg("parse dns message questions error")
	}

	question := msg.Questions[0]
	log.Info().Stringer("remote_ip", addr).Str("msg_header", msg.Header.GoString()).Str("msg_question", question.GoString()).Msg("parse dns message ok")

	switch question.Type {
	case dnsmessage.TypeA, dnsmessage.TypeAAAA:
		break
	default:
		return
	}

	name := question.Name.String()
	as := make([][4]byte, 0)

	switch name {
	case "1.0.0.127.in-addr.arpa.":
		as = append(as, [4]byte{127, 0, 0, 1})
	default:
		hosts, _ := h.resolvers[0].LookupHost(context.Background(), name[:len(name)-2])
		for _, s := range hosts {
			var a [4]byte
			copy(a[:], net.ParseIP(s))
			as = append(as, a)
		}
	}

	for _, a := range as {
		msg.Answers = append(msg.Answers, dnsmessage.Resource{
			dnsmessage.ResourceHeader{
				Name:  dnsmessage.MustNewName(name),
				Type:  dnsmessage.TypeA,
				Class: dnsmessage.ClassINET,
				TTL:   600,
			},
			&dnsmessage.AResource{a},
		})
	}

	resp, err := msg.Pack()
	if err != nil {
		log.Error().Err(err).Stringer("remote_ip", addr).Str("msg_header", msg.Header.GoString()).Interface("msg_questions", msg.Questions[0]).Interface("msg_answers", msg.Answers[0]).Msg("pack dns message answers error")
	}

	conn.WriteTo(resp, addr)
	log.Info().Stringer("remote_ip", addr).Str("msg_header", msg.Header.GoString()).Str("msg_question", question.GoString()).Interface("msg_answers", msg.Answers[0]).Msg("write msg answsers")
}
