package main

import (
	"context"
	"net"

	"github.com/phuslu/log"
	"github.com/tidwall/shardmap"
)

type Resolver struct {
	*net.Resolver
	DNSCacheTTL uint32

	cache shardmap.Map
}

type ResolverCacheItem struct {
	A []net.IP

	expires int64
}

func (r *Resolver) LookupIP(ctx context.Context, name string) ([]net.IP, error) {
	return r.lookupIP(ctx, name)
}

func (r *Resolver) lookupIP(ctx context.Context, name string) ([]net.IP, error) {
	if v, ok := r.cache.Get(name); ok {
		item := v.(ResolverCacheItem)
		if item.expires > unix() {
			return item.A, nil
		}
		r.cache.Delete(name)
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

	if r.DNSCacheTTL > 0 && len(ips) > 0 {
		r.cache.Set(name, ResolverCacheItem{ips, unix() + int64(r.DNSCacheTTL)})
	}

	log.Debug().Msgf("lookupIP(%#v) return %+v", name, ips)
	return ips, nil
}
