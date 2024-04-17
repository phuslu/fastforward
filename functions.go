package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/phuslu/geosite"
	"github.com/phuslu/log"
	"github.com/phuslu/lru"
	"github.com/puzpuzpuz/xsync/v3"
)

type Functions struct {
	RegionResolver *RegionResolver
	GeoSite        *geosite.DomainListCommunity
	Singleflight   *singleflight_Group[string, string]
	IPListCache    *lru.TTLCache[string, *string]
	GeoSiteCache   *lru.TTLCache[string, *string]
	RegexpCache    *xsync.MapOf[string, *regexp.Regexp]

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

	f.FuncMap = template.FuncMap{}
	f.FuncMap["city"] = f.city
	f.FuncMap["country"] = f.country
	f.FuncMap["geoip"] = f.geoip
	f.FuncMap["geosite"] = f.geosite
	f.FuncMap["greased"] = f.greased
	f.FuncMap["host"] = f.host
	f.FuncMap["iplist"] = f.iplist
	f.FuncMap["readfile"] = f.readfile
	f.FuncMap["region"] = f.region

	// sprig copycat
	f.FuncMap["regexMatch"] = f.regexMatch
	f.FuncMap["contains"] = f.contains
	f.FuncMap["hasPrefix"] = f.hasPrefix
	f.FuncMap["hasSuffix"] = f.hasSuffix
	f.FuncMap["empty"] = f.empty
	f.FuncMap["all"] = f.all
	f.FuncMap["any"] = f.any
	f.FuncMap["ternary"] = f.ternary

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
	if v, _ := f.IPListCache.Get(iplistUrl); v != nil {
		return *v
	}

	body, err, _ := f.Singleflight.Do(iplistUrl, func() (string, error) {
		data, err := ReadFile(iplistUrl)
		return string(data), err
	})
	if err != nil {
		log.Error().Err(err).Str("iplist_url", iplistUrl).Msg("read iplist url error")
		return "[]"
	}

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
	f.IPListCache.Set(iplistUrl, &data, 12*time.Hour)

	return data
}

func (f *Functions) geosite(domain string) string {
	if host, _, err := net.SplitHostPort(domain); err == nil {
		domain = host
	}

	if v, _ := f.GeoSiteCache.Get(domain); v != nil {
		return *v
	}

	site := f.GeoSite.Site(domain)

	f.GeoSiteCache.Set(domain, &site, 24*time.Hour)

	return site
}

func (f *Functions) readfile(filename string) string {
	data, _ := os.ReadFile(filename)
	return string(data)
}

func (f *Functions) contains(substr, s string) bool {
	return strings.Contains(s, substr)
}

func (f *Functions) hasSuffix(suffix, s string) bool {
	return strings.HasSuffix(s, suffix)
}

func (f *Functions) hasPrefix(suffix, s string) bool {
	return strings.HasPrefix(s, suffix)
}

func (f *Functions) regexMatch(pattern, s string) bool {
	regex, _ := f.RegexpCache.LoadOrCompute(pattern, func() *regexp.Regexp {
		v, _ := regexp.Compile(pattern)
		return v
	})
	if regex == nil {
		return false
	}
	return regex.MatchString(s)
}

func (f *Functions) empty(given interface{}) bool {
	g := reflect.ValueOf(given)
	if !g.IsValid() {
		return true
	}

	// Basically adapted from text/template.isTrue
	switch g.Kind() {
	default:
		return g.IsNil()
	case reflect.Array, reflect.Slice, reflect.Map, reflect.String:
		return g.Len() == 0
	case reflect.Bool:
		return !g.Bool()
	case reflect.Complex64, reflect.Complex128:
		return g.Complex() == 0
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return g.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return g.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return g.Float() == 0
	case reflect.Struct:
		return false
	}
}

func (f *Functions) all(v ...interface{}) bool {
	for _, val := range v {
		if f.empty(val) {
			return false
		}
	}
	return true
}

func (f *Functions) any(v ...interface{}) bool {
	for _, val := range v {
		if !f.empty(val) {
			return true
		}
	}
	return false
}

func (f *Functions) ternary(vt interface{}, vf interface{}, v bool) interface{} {
	if v {
		return vt
	}

	return vf
}
