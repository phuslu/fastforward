package main

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/phuslu/log"
	"github.com/phuslu/lru"
)

type Resolver struct {
	*net.Resolver
	LRUCache      *lru.TTLCache[string, []netip.Addr]
	CacheDuration time.Duration
}

func (r *Resolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if r.LRUCache != nil {
		if v, ok := r.LRUCache.Get(host); ok {
			return v, nil
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
		r.LRUCache.Set(host, ips, r.CacheDuration)
	}

	log.Debug().Msgf("lookupIP(%#v) return %+v", host, ips)
	return ips, nil
}
