package main

import (
	"context"
	"testing"
)

func TestRegionResolver(t *testing.T) {
	var pairs = [][2]string{
		{"192.168.1.1", ""},
		{"localhost", ""},
		{"hk.phus.lu", "HK"},
		{"kr.phus.lu", "KR"},
	}

	r := &RegionResolver{
		Resolver: &Resolver{},
	}

	for _, pair := range pairs {
		host, country := pair[0], pair[1]
		if c, _ := r.LookupCountry(context.Background(), host); c != country {
			t.Errorf("LookupCountry(%#v) return %#v,  not match %#v", host, c, country)
		}
	}
}
