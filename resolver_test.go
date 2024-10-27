package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/phuslu/fastdns"
	"github.com/phuslu/lru"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestResolver(t *testing.T) {
	r := &Resolver{
		Client: &fastdns.Client{
			Addr: "1.1.1.1:53",
		},
		CacheDuration: time.Minute,
		LRUCache:      lru.NewTTLCache[string, []netip.Addr](32 * 1024),
	}

	fmt.Println(r.LookupNetIP(context.Background(), "ip", "gmail.com"))
}

func TestResolverDoH(t *testing.T) {
	cases := []struct {
		Host string
		IP   string
	}{
		{"192-168-2-1.nip.io", "192.168.2.1"},
		{"forcesafesearch.google.com", "216.239.38.120"},
	}

	doh := "https://1.1.1.1/dns-query"

	client := &fastdns.Client{
		Addr: doh,
		Dialer: &fastdns.HTTPDialer{
			Endpoint: func() (u *url.URL) { u, _ = url.Parse(doh); return }(),
		},
	}

	for _, c := range cases {
		v, err := client.LookupNetIP(context.Background(), "ip4", c.Host)
		// t.Logf("LookupAddr(%#v) return v=%+v err=%+v", c.Host, v, err)
		if err != nil || v[0].String() != c.IP {
			t.Errorf("LookupAddr(%#v) must return %#v, not %+v, err=%+v", c.Host, c.IP, v, err)
		}
	}
}

func TestResolverDoH3(t *testing.T) {
	cases := []struct {
		Host string
		IP   string
	}{
		{"192-168-2-1.nip.io", "192.168.2.1"},
		{"forcesafesearch.google.com", "216.239.38.120"},
	}

	doh := "https://1.1.1.1/dns-query"

	client := &fastdns.Client{
		Addr: doh,
		Dialer: &fastdns.HTTPDialer{
			Endpoint: func() (u *url.URL) { u, _ = url.Parse(doh); return }(),
			Header: http.Header{
				"content-type": {"application/dns-message"},
				"user-agent":   {"fastdns/1.0"},
			},
			Transport: &http3.Transport{
				DisableCompression: false,
				EnableDatagrams:    true,
				TLSClientConfig: &tls.Config{
					NextProtos:         []string{"h3"},
					InsecureSkipVerify: true,
					ServerName:         "1.1.1.1",
					ClientSessionCache: tls.NewLRUClientSessionCache(128),
				},
				QUICConfig: &quic.Config{
					DisablePathMTUDiscovery: false,
					EnableDatagrams:         true,
					MaxIncomingUniStreams:   200,
					MaxIncomingStreams:      200,
				},
			},
		},
	}

	for _, c := range cases {
		v, err := client.LookupNetIP(context.Background(), "ip4", c.Host)
		// t.Logf("LookupAddr(%#v) return v=%+v err=%+v", c.Host, v, err)
		if err != nil || v[0].String() != c.IP {
			t.Errorf("LookupAddr(%#v) must return %#v, not %+v, err=%+v", c.Host, c.IP, v, err)
		}
	}
}
