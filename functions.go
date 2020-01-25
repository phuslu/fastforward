package main

import (
	"context"
	"crypto/tls"
	"net"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/phuslu/geoip"
	"github.com/phuslu/log"
)

type Functions struct {
	RegionResolver *RegionResolver
}

func (f *Functions) FuncMap() template.FuncMap {
	var m = sprig.TxtFuncMap()

	m["all"] = f.all
	m["any"] = f.any
	m["city"] = f.city
	m["country"] = f.country
	m["geoip"] = f.geoip
	m["greased"] = f.greased
	m["region"] = f.region

	return m
}

func (f *Functions) all(b ...interface{}) bool {
	for _, v := range b {
		if truth, _ := template.IsTrue(v); !truth {
			return false
		}
	}
	return true
}

func (f *Functions) any(b ...interface{}) bool {
	for _, v := range b {
		if truth, _ := template.IsTrue(v); truth {
			return true
		}
	}
	return false
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

	return string(geoip.Country(net.ParseIP(ip)))
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
