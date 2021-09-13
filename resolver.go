package main

import (
	"context"
	"net"
	"time"

	"github.com/cloudflare/golibs/lrucache"
	"github.com/phuslu/log"
)

type Resolver struct {
	*net.Resolver
	LRUCache      lrucache.Cache
	CacheDuration time.Duration
}

func (r *Resolver) LookupIP(ctx context.Context, name string) ([]net.IP, error) {
	return r.lookupIP(ctx, name)
}

func (r *Resolver) lookupIP(ctx context.Context, name string) ([]net.IP, error) {
	if r.LRUCache != nil {
		if v, ok := r.LRUCache.GetNotStale(name); ok {
			return v.([]net.IP), nil
		}
	}

	if ip := net.ParseIP(name); ip != nil {
		return []net.IP{ip}, nil
	}

	addrs, err := r.Resolver.LookupIPAddr(ctx, name)
	if err != nil {
		return nil, err
	}

	ips := make([]net.IP, len(addrs))
	for i, ia := range addrs {
		ips[i] = ia.IP
	}

	if r.LRUCache != nil && r.CacheDuration > 0 && len(ips) > 0 {
		r.LRUCache.Set(name, ips, timeNow().Add(r.CacheDuration))
	}

	log.Debug().Msgf("lookupIP(%#v) return %+v", name, ips)
	return ips, nil
}
