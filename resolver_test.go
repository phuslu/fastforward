package main

import (
	"context"
	"net"
	"testing"
)

func TestDoHResolver(t *testing.T) {
	cases := []struct {
		Host string
		IP   string
	}{
		{"192-168-2-1.nip.io", "192.168.2.1"},
		{"forcesafesearch.google.com", "216.239.38.120"},
	}

	r := &net.Resolver{
		PreferGo: true,
		Dial: (&DoHResolverDialer{
			EndPoint:  "https://dns.google/dns-query",
			UserAgent: DefaultUserAgent,
		}).DialContext,
	}

	for _, c := range cases {
		v, err := r.LookupHost(context.Background(), c.Host)
		// t.Logf("LookupAddr(%#v) return v=%+v err=%+v", c.Host, v, err)
		if err != nil || v[0] != c.IP {
			t.Errorf("LookupAddr(%#v) must return %#v, not %+v, err=%+v", c.Host, c.IP, v, err)
		}
	}
}
