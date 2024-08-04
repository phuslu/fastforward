package main

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/go-task/slim-sprig/v3"
	"github.com/phuslu/geosite"
	"github.com/phuslu/log"
	"github.com/phuslu/lru"
	"github.com/puzpuzpuz/xsync/v3"
	"golang.org/x/net/publicsuffix"
)

type Functions struct {
	GeoResolver  *GeoResolver
	GeoSite      *geosite.DomainListCommunity
	FetchClient  *http.Client
	FetchCache   *lru.TTLCache[string, *FetchResponse]
	GeoSiteCache *lru.TTLCache[string, *string]
	RegexpCache  *xsync.MapOf[string, *regexp.Regexp]

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

	f.FuncMap = template.FuncMap(sprig.GenericFuncMap())

	// sprig supplement
	f.FuncMap["hasPrefixes"] = f.hasPrefixes
	f.FuncMap["hasSuffixes"] = f.hasSuffixes
	f.FuncMap["regexMatch"] = f.regexMatch
	f.FuncMap["wildcardMatch"] = f.wildcardMatch

	// http related
	f.FuncMap["country"] = f.country
	f.FuncMap["dnsResolve"] = f.dnsResolve
	f.FuncMap["domain"] = f.domain
	f.FuncMap["fetch"] = f.fetch
	f.FuncMap["geoip"] = f.geoip
	f.FuncMap["geosite"] = f.geosite
	f.FuncMap["greased"] = f.greased
	f.FuncMap["host"] = f.host
	f.FuncMap["ipRange"] = f.ipRange
	f.FuncMap["readfile"] = f.readfile

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
	Domain  string
}

func (f *Functions) geoip(ipStr string) GeoipInfo {
	if s, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = s
	}

	ip := net.ParseIP(ipStr)

	if ip == nil {
		ips, _ := f.GeoResolver.Resolver.LookupNetIP(context.Background(), "ip", ipStr)
		if len(ips) == 0 {
			return GeoipInfo{Country: "ZZ"}
		}
		ip = net.IP(ips[0].AsSlice())
	}

	var country, region, city string
	if f.GeoResolver.CityReader != nil {
		country, region, city, _ = f.GeoResolver.LookupCity(context.Background(), ip)
	}

	if country == "CN" && IsBogusChinaIP(ip) {
		return GeoipInfo{Country: "ZZ"}
	}

	log.Debug().IPAddr("ip", ip).Str("country", country).Str("region", region).Str("city", city).Msg("get city by ip")

	var domain string
	if f.GeoResolver.DomainReader != nil {
		domain, _ = f.GeoResolver.LookupDomain(context.Background(), ip)
		log.Debug().IPAddr("ip", ip).Str("domain", domain).Msg("get domain by ip")
	}

	return GeoipInfo{
		Country: country,
		Region:  region,
		City:    city,
		Domain:  domain,
	}
}

func (f *Functions) country(ip string) string {
	return f.geoip(ip).Country
}

func (f *Functions) dnsResolve(host string) string {
	if s, _, err := net.SplitHostPort(host); err == nil {
		host = s
	}

	ips, _ := f.GeoResolver.Resolver.LookupNetIP(context.Background(), "ip", host)
	if len(ips) != 0 {
		return ips[0].String()
	}

	return ""
}

func (f *Functions) domain(domain string) string {
	s, _ := publicsuffix.EffectiveTLDPlusOne(domain)
	return s
}

func (f *Functions) greased(info *tls.ClientHelloInfo) bool {
	if info == nil || len(info.CipherSuites) == 0 {
		return false
	}
	c := info.CipherSuites[0]
	return c&0x0f0f == 0x0a0a && c&0xff == c>>8
}

type FetchResponse struct {
	Status    int
	Headers   http.Header
	Body      string
	Lines     []string
	Error     error
	CreatedAt time.Time
}

func (f *Functions) fetch(timeout, cacheSeconds int, uri string) (response FetchResponse) {
	loader := func(ctx context.Context, s string) (*FetchResponse, time.Duration, error) {
		ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
		if err != nil {
			log.Error().Str("fetch_url", uri).AnErr("fetch_error", err).Msg("fetch error")
			return &FetchResponse{Error: err}, time.Duration(min(cacheSeconds, 60)) * time.Second, nil
		}

		resp, err := f.FetchClient.Do(req)
		if err != nil {
			log.Error().Str("fetch_url", uri).AnErr("fetch_error", err).Msg("fetch error")
			return &FetchResponse{Error: err}, time.Duration(min(cacheSeconds, 60)) * time.Second, nil
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error().Str("fetch_url", uri).AnErr("fetch_error", err).Msg("fetch error")
			return &FetchResponse{Error: err}, time.Duration(min(cacheSeconds, 60)) * time.Second, nil
		}

		result := &FetchResponse{
			Status:    resp.StatusCode,
			Headers:   resp.Header,
			Body:      string(body),
			CreatedAt: time.Now(),
		}

		if strings.HasPrefix(result.Headers.Get("content-type"), "text/") {
			result.Lines = strings.Split(result.Body, "\n")
		}

		log.Info().Str("fetch_url", uri).Int("fetch_response_status", result.Status).Any("fetch_response_headers", result.Headers).Int("fetch_response_length", len(result.Body)).Msg("fetch ok")

		return result, time.Duration(cacheSeconds), nil
	}

	resp, _, _ := f.FetchCache.GetOrLoad(context.Background(), uri, loader)
	if resp == nil {
		return
	}

	response = *resp
	return
}

func (f *Functions) ipRange(cidr string) (result IPRange) {
	result, _ = GetIPRange(strings.TrimSpace(cidr))
	return
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

func (f *Functions) hasSuffixes(pattern, s string) bool {
	for pattern != "" {
		var p string
		i := strings.IndexByte(pattern, '|')
		if i < 0 {
			p, pattern = pattern, ""
		} else {
			p, pattern = pattern[:i], pattern[i+1:]
		}
		if strings.HasSuffix(s, p) {
			return true
		}
	}
	return false
}

func (f *Functions) hasPrefixes(pattern, s string) bool {
	for pattern != "" {
		var p string
		i := strings.IndexByte(pattern, '|')
		if i < 0 {
			p, pattern = pattern, ""
		} else {
			p, pattern = pattern[:i], pattern[i+1:]
		}
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func (f *Functions) wildcardMatch(pattern, s string) bool {
	for pattern != "" {
		var p string
		i := strings.IndexByte(pattern, '|')
		if i < 0 {
			p, pattern = pattern, ""
		} else {
			p, pattern = pattern[:i], pattern[i+1:]
		}
		if WildcardMatch(p, s) {
			return true
		}
	}
	return false
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
