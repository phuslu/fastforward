package main

import (
	"context"
	"crypto/tls"
	"net"
	"text/template"

	"github.com/Masterminds/sprig"
	"github.com/phuslu/log"
)

type Functions struct {
	RegionResolver *RegionResolver
}

func (f *Functions) FuncMap() template.FuncMap {
	var m = sprig.TxtFuncMap()

	m["all"] = f.all
	m["any"] = f.any
	m["geoip"] = f.geoip
	m["greased"] = f.greased

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

func (f *Functions) geoip(ip string) map[string]string {
	if s, _, err := net.SplitHostPort(ip); err == nil {
		ip = s
	}

	if net.ParseIP(ip) == nil {
		ips, _ := f.RegionResolver.Resolver.LookupIP(context.Background(), ip)
		if len(ips) == 0 {
			return map[string]string{"Country": "ZZ", "Region": "", "City": ""}
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
		return map[string]string{"Country": "ZZ", "Region": "", "City": ""}
	}

	log.Debug().Str("ip", ip).Str("country", country).Str("region", region).Str("city", city).Msg("get city by ip")

	return map[string]string{
		"Country": country,
		"Region":  region,
		"City":    city,
	}
}

func (f *Functions) greased(info *tls.ClientHelloInfo) bool {
	if info == nil || len(info.CipherSuites) == 0 {
		return false
	}
	c := info.CipherSuites[0]
	return c&0x0f0f == 0x0a0a && c&0xff == c>>8
}
