package main

import (
	"cmp"
	"context"
	"net/netip"
	"slices"
	"time"

	"github.com/phuslu/fastdns"
	"github.com/phuslu/log"
	"github.com/phuslu/lru"
)

type Resolver struct {
	*fastdns.Client
	CacheDuration time.Duration

	LRUCache *lru.TTLCache[string, []netip.Addr]
}

func (r *Resolver) LookupNetIP(ctx context.Context, network, host string) (ips []netip.Addr, err error) {
	if r.LRUCache != nil {
		if v, ok := r.LRUCache.Get(host); ok {
			return v, nil
		}
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip}, nil
	}

	ips, err = r.Client.AppendLookupNetIP(ips, ctx, network, host)
	if err != nil {
		return nil, err
	}

	slices.SortStableFunc(ips, func(a, b netip.Addr) int { return cmp.Compare(btoi(b.Is4()), btoi(a.Is4())) })

	if r.LRUCache != nil && r.CacheDuration > 0 && len(ips) > 0 {
		r.LRUCache.Set(host, ips, r.CacheDuration)
	}

	log.Debug().Str("host", host).Str("dns_server", r.Client.Addr).Any("ips", ips).Msg("LookupNetIP")
	return ips, nil
}
