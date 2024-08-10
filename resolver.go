package main

import (
	"cmp"
	"context"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/phuslu/log"
	"github.com/phuslu/lru"
)

type Resolver struct {
	*net.Resolver
	CacheDuration time.Duration

	LRUCache *lru.TTLCache[string, []netip.Addr]
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

	slices.SortStableFunc(ips, func(a, b netip.Addr) int { return cmp.Compare(btoi(b.Is4()), btoi(a.Is4())) })

	if r.LRUCache != nil && r.CacheDuration > 0 && len(ips) > 0 {
		r.LRUCache.Set(host, ips, r.CacheDuration)
	}

	log.Debug().Msgf("lookupIP(%#v) return %+v", host, ips)
	return ips, nil
}
