package main

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/cloudflare/golibs/lrucache"
	"github.com/phuslu/log"
)

type Resolver struct {
	*net.Resolver
	LRUCache      lrucache.Cache
	CacheDuration time.Duration
}

func (r *Resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if r.LRUCache != nil {
		if v, ok := r.LRUCache.GetNotStale(host); ok {
			return v.([]netip.Addr), nil
		}
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}

	ips, err := r.Resolver.LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, err
	}

	if r.LRUCache != nil && r.CacheDuration > 0 && len(ips) > 0 {
		r.LRUCache.Set(host, ips, timeNow().Add(r.CacheDuration))
	}

	log.Debug().Msgf("lookupIP(%#v) return %+v", host, ips)
	return ips, nil
}
