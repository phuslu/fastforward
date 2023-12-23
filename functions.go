package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig/v3"
	"github.com/phuslu/geosite"
	"github.com/phuslu/log"
	"github.com/phuslu/lru"
	"golang.org/x/sync/singleflight"
)

type Functions struct {
	RegionResolver *RegionResolver
	GeoSite        *geosite.DomainListCommunity
	Singleflight   *singleflight.Group
	IPListCache    *lru.Cache[string, *string]
	GeoSiteCache   *lru.Cache[string, *string]

	FuncMap template.FuncMap
}

func (f *Functions) Load() error {
	if names, _ := filepath.Glob("*domain-list-community*.tar.gz"); len(names) > 0 {
		for _, name := range names {
			if err := f.GeoSite.Load(context.Background(), name); err != nil {
				return err
			}
		}
	} else {
		if err := f.GeoSite.Load(context.Background(), geosite.InlineTarball); err != nil {
			return err
		}
	}

	go func() {
		for range time.Tick(time.Hour) {
			if err := f.GeoSite.Load(context.Background(), geosite.OnlineTarball); err != nil {
				log.Error().Err(err).Str("geosite_online_tarball", geosite.OnlineTarball).Msg("geosite load error")
			}
		}
	}()

	f.FuncMap = sprig.TxtFuncMap()
	f.FuncMap["city"] = f.city
	f.FuncMap["country"] = f.country
	f.FuncMap["geoip"] = f.geoip
	f.FuncMap["geosite"] = f.geosite
	f.FuncMap["greased"] = f.greased
	f.FuncMap["host"] = f.host
	f.FuncMap["iplist"] = f.iplist
	f.FuncMap["readfile"] = f.readfile
	f.FuncMap["region"] = f.region

	return nil
}

func (f *Functions) host(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
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
		ips, _ := f.RegionResolver.Resolver.LookupNetIP(context.Background(), "ip", ip)
		if len(ips) == 0 {
			return GeoipInfo{Country: "ZZ"}
		}
		ip = ips[0].String()
	}

	var country, region, city string
	if f.RegionResolver.MaxmindReader != nil {
		country, region, city, _ = f.RegionResolver.LookupCity(context.Background(), net.ParseIP(ip))
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

func (f *Functions) country(ip string) string {
	return f.geoip(ip).Country
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
	if v := f.IPListCache.Get(iplistUrl); v != nil {
		return *v
	}

	v, err, _ := f.Singleflight.Do(iplistUrl, func() (interface{}, error) {
		body, err := ReadFile(iplistUrl)
		return string(body), err
	})
	if err != nil {
		log.Error().Err(err).Str("iplist_url", iplistUrl).Msg("read iplist url error")
		return "[]"
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
	f.IPListCache.SetWithTTL(iplistUrl, &data, 12*time.Hour)

	return data
}

func (f *Functions) geosite(domain string) string {
	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}

	if v := f.GeoSiteCache.Get(domain); v != nil {
		return *v
	}

	site := f.GeoSite.Site(domain)

	f.GeoSiteCache.SetWithTTL(domain, &site, 24*time.Hour)

	return site
}

func (f *Functions) readfile(filename string) string {
	data, _ := os.ReadFile(filename)
	return string(data)
}
