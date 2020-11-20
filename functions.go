package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig"
	"github.com/phuslu/iploc"
	"github.com/phuslu/log"
	"github.com/tidwall/shardmap"
	"golang.org/x/sync/singleflight"
)

type Functions struct {
	Singleflight   *singleflight.Group
	RegionResolver *RegionResolver
	shardmap       shardmap.Map
}

func (f *Functions) FuncMap() template.FuncMap {
	var m = sprig.TxtFuncMap()

	m["all"] = f.all
	m["any"] = f.any
	m["host"] = f.host
	m["city"] = f.city
	m["country"] = f.country
	m["geoip"] = f.geoip
	m["greased"] = f.greased
	m["region"] = f.region
	m["iplist"] = f.iplist
	m["isdir"] = f.isdir
	m["isfile"] = f.isfile
	m["tryfiles"] = f.tryfiles

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

func (f *Functions) isdir(filename string) bool {
	fi, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return fi.IsDir()
}

func (f *Functions) isfile(filename string) bool {
	fi, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return !fi.IsDir()
}

func (f *Functions) tryfiles(files ...string) string {
	for _, file := range files {
		data, err := ioutil.ReadFile(file)
		if err == nil {
			return string(data)
		}
	}
	return ""
}

type IPListItem struct {
	Time time.Time
	Data string
}

func (f *Functions) iplist(iplistUrl string) string {
	v, ok := f.shardmap.Get(iplistUrl)
	if ok {
		item := v.(IPListItem)
		if timeNow().Sub(item.Time) < 12*time.Hour {
			return item.Data
		}
		f.shardmap.Delete(iplistUrl)
	}

	v, err, _ := f.Singleflight.Do(iplistUrl, func() (interface{}, error) {
		return ReadFile(iplistUrl)
	})
	if err != nil {
		log.Error().Err(err).Str("iplist_url", iplistUrl).Msg("read iplist url error")
		return "[]"
	}

	body := v.([]byte)

	iplist, err := MergeCIDRToIPList(bytes.NewReader(body))
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
	f.shardmap.Set(iplistUrl, IPListItem{timeNow(), data})

	return data
}
