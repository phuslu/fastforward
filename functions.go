package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/cloudflare/golibs/lrucache"
	"github.com/phuslu/iploc"
	"github.com/phuslu/log"
	"golang.org/x/sync/singleflight"
)

type Functions struct {
	Singleflight   *singleflight.Group
	RegionResolver *RegionResolver
	LRUCache       lrucache.Cache
}

func (f *Functions) FuncMap() template.FuncMap {
	var m = sprig.TxtFuncMap()

	m["host"] = f.host
	m["city"] = f.city
	m["country"] = f.country
	m["geoip"] = f.geoip
	m["greased"] = f.greased
	m["region"] = f.region
	m["iplist"] = f.iplist

	return m
}

func (f *Functions) host(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

func (f *Functions) country(ip string) string {
	if s, _, err := net.SplitHostPort(ip); err == nil {
		ip = s
	}

	if net.ParseIP(ip) == nil {
		ips, _ := f.RegionResolver.Resolver.LookupIP(context.Background(), ip)
		if len(ips) == 0 {
			return "ZZ"
		}
		ip = ips[0].String()
	}

	return string(iploc.Country(net.ParseIP(ip)))
}

type GeoipInfo struct {
	Country string
	Region  string
	City    string
}

func (f *Functions) geoip(ip string) GeoipInfo {
	if s, _, err := net.SplitHostPort(ip); err == nil {
		ip = s
	}

	if net.ParseIP(ip) == nil {
		ips, _ := f.RegionResolver.Resolver.LookupIP(context.Background(), ip)
		if len(ips) == 0 {
			return GeoipInfo{Country: "ZZ"}
		}
		ip = ips[0].String()
	}

	var country, region, city string
	if f.RegionResolver.MaxmindReader != nil {
		country, region, city, _ = f.RegionResolver.LookupCity(context.Background(), net.ParseIP(ip))
	} else {
		country, _ = f.RegionResolver.LookupCountry(context.Background(), ip)
	}

	if country == "CN" && IsBogusChinaIP(net.ParseIP(ip)) {
		return GeoipInfo{Country: "ZZ"}
	}

	log.Debug().Str("ip", ip).Str("country", country).Str("region", region).Str("city", city).Msg("get city by ip")

	return GeoipInfo{
		Country: country,
		Region:  region,
		City:    city,
	}
}

func (f *Functions) region(ip string) string {
	return f.geoip(ip).Region
}

func (f *Functions) city(ip string) string {
	return f.geoip(ip).City
}

func (f *Functions) greased(info *tls.ClientHelloInfo) bool {
	if info == nil || len(info.CipherSuites) == 0 {
		return false
	}
	c := info.CipherSuites[0]
	return c&0x0f0f == 0x0a0a && c&0xff == c>>8
}

func (f *Functions) iplist(iplistUrl string) string {
	var err error

	v, ok := f.LRUCache.GetNotStale(iplistUrl)
	if !ok {
		v, err, _ = f.Singleflight.Do(iplistUrl, func() (interface{}, error) {
			return ReadFile(iplistUrl)
		})
		if err != nil {
			log.Error().Err(err).Str("iplist_url", iplistUrl).Msg("read iplist url error")
			return "[]"
		}
	}

	body := v.(string)

	iplist, err := MergeCIDRToIPList(strings.NewReader(body))
	if err != nil {
		log.Error().Err(err).Str("iplist_url", iplistUrl).Msg("parse iplist url error")
		return "[]"
	}

	var sb strings.Builder
	sb.WriteByte('[')
	for i := 0; i < len(iplist); i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		if i%2 == 0 {
			fmt.Fprintf(&sb, "%d", iplist[i])
		} else {
			fmt.Fprintf(&sb, "%d", iplist[i]-iplist[i-1])
		}
	}
	sb.WriteByte(']')

	data := sb.String()
	f.LRUCache.Set(iplistUrl, data, time.Now().Add(12*time.Hour))

	return data
}
