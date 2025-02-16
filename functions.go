package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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
	Context context.Context

	GeoResolver *GeoResolver
	GeoCache    *lru.TTLCache[string, *GeoipInfo]

	GeoSite      *geosite.DomainListCommunity
	GeoSiteCache *lru.TTLCache[string, *string]

	FetchUserAgent string
	FetchClient    *http.Client
	FetchCache     *lru.TTLCache[string, *FetchResponse]

	RegexpCache *xsync.MapOf[string, *regexp.Regexp]
	FileCache   *xsync.MapOf[string, *FileLoader[[]string]]

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
	f.FuncMap["hasIPv6"] = f.hasIPv6
	f.FuncMap["host"] = f.host
	f.FuncMap["ipInt"] = f.ipInt
	f.FuncMap["ipRange"] = f.ipRange
	f.FuncMap["isInNet"] = f.isInNet

	// file related
	f.FuncMap["infile"] = f.infile
	f.FuncMap["inFile"] = f.infile
	f.FuncMap["infile2"] = f.infile2
	f.FuncMap["inFile2"] = f.infile2
	f.FuncMap["readfile"] = f.readfile
	f.FuncMap["readFile"] = f.readfile

	return nil
}

func (f *Functions) WithContext(ctx context.Context) *Functions {
	fn := *f
	fn.Context = ctx
	return &fn
}

func (f *Functions) host(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

type GeoipInfo struct {
	IP             string
	Country        string
	City           string
	ISP            string
	ASN            string
	Domain         string
	ConnectionType string
}

func (f *Functions) geoip(ipStr string) GeoipInfo {
	loader := func(ctx context.Context, ipStr string) (*GeoipInfo, time.Duration, error) {
		ip := net.ParseIP(ipStr)

		if ip == nil {
			ips, _ := f.GeoResolver.Resolver.LookupNetIP(ctx, "ip", ipStr)
			if len(ips) == 0 {
				return &GeoipInfo{IP: ipStr, Country: "ZZ"}, time.Minute, nil
			}
			ip = net.IP(ips[0].AsSlice())
		}

		var country, city string
		if f.GeoResolver.CityReader != nil {
			country, city, _ = f.GeoResolver.LookupCity(ctx, ip)
		}

		if country == "CN" && IsBogusChinaIP(ip) {
			return &GeoipInfo{IP: ipStr, Country: "ZZ"}, time.Minute, nil
		}

		log.Debug().IPAddr("ip", ip).Str("country", country).Str("city", city).Msg("get city by ip")

		result := &GeoipInfo{
			IP:      ipStr,
			Country: country,
			City:    city,
		}

		if f.GeoResolver.ISPReader != nil {
			if isp, asn, err := f.GeoResolver.LookupISP(ctx, ip); err == nil {
				result.ISP = isp
				result.ASN = fmt.Sprintf("AS%d", asn)
				log.Debug().IPAddr("ip", ip).Str("isp", isp).Uint("asn", asn).Msg("get isp by ip")
			}
		}

		if f.GeoResolver.DomainReader != nil {
			if domain, err := f.GeoResolver.LookupDomain(ctx, ip); err == nil {
				result.Domain = domain
				log.Debug().IPAddr("ip", ip).Str("domain", domain).Msg("get domain by ip")
			}
		}

		if f.GeoResolver.ConnectionTypeReader != nil {
			if conntype, err := f.GeoResolver.LookupConnectionType(ctx, ip); err == nil {
				result.ConnectionType = conntype
				log.Debug().IPAddr("ip", ip).Str("connection_type", conntype).Msg("get connection_type by ip")
			}
		}

		return result, 12 * time.Hour, nil
	}

	if s, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = s
	}

	info, _, _ := f.GeoCache.GetOrLoad(context.Background(), ipStr, loader)
	if info == nil {
		return GeoipInfo{}
	}

	return *info
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
	if s, _, err := net.SplitHostPort(domain); err == nil {
		domain = s
	}

	if net.ParseIP(domain) != nil {
		return domain
	}

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

func (f *Functions) fetch(ua string, timeout, ttl int, uri string) (response FetchResponse) {
	loader := func(ctx context.Context, uri string) (*FetchResponse, time.Duration, error) {
		ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, uri, nil)
		if err != nil {
			log.Error().Str("fetch_url", uri).AnErr("fetch_error", err).Msg("fetch error")
			return &FetchResponse{Error: err}, time.Duration(min(ttl, 60)) * time.Second, nil
		}
		if ua != "" {
			req.Header.Set("User-Agent", ua)
		} else {
			req.Header.Set("User-Agent", f.FetchUserAgent)
		}

		resp, err := f.FetchClient.Do(req)
		if err != nil {
			log.Error().Str("fetch_url", uri).AnErr("fetch_error", err).Msg("fetch error")
			return &FetchResponse{Error: err}, time.Duration(min(ttl, 60)) * time.Second, nil
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Error().Str("fetch_url", uri).AnErr("fetch_error", err).Msg("fetch error")
			return &FetchResponse{Error: err}, time.Duration(min(ttl, 60)) * time.Second, nil
		}

		result := &FetchResponse{
			Status:    resp.StatusCode,
			Headers:   resp.Header,
			Body:      string(body),
			CreatedAt: time.Now(),
		}

		if strings.HasPrefix(result.Headers.Get("content-type"), "text/") {
			// result.Lines = strings.Split(result.Body, "\n")
			result.Lines = AppendSplitLines(make([]string, 0, strings.Count(result.Body, "\n")), result.Body)
		}

		log.Info().Str("fetch_url", uri).Int("fetch_response_status", result.Status).Any("fetch_response_headers", result.Headers).Int("fetch_response_length", len(result.Body)).Msg("fetch ok")

		return result, time.Duration(ttl), nil
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

func (f *Functions) ipInt(ipStr string) uint {
	return uint(NewIPInt(ipStr))
}

func (f *Functions) isInNet(host, cidr string) bool {
	if s, _, err := net.SplitHostPort(host); err == nil {
		host = s
	}

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		log.Error().Err(err).Str("host", host).Str("cidr", cidr).Msg("isInNet ParsePrefix error")
		return false
	}

	ip, err := netip.ParseAddr(host)
	if err != nil {
		ips, err := f.GeoResolver.Resolver.LookupNetIP(context.Background(), "ip", host)
		if err != nil {
			log.Error().Err(err).Str("host", host).Str("cidr", cidr).Msg("isInNet LookupNetIP error")
		}
		if len(ips) == 0 {
			return false
		}
		ip = ips[0]
	}

	return prefix.Contains(ip)
}

func (f *Functions) hasIPv6(host string) bool {
	if s, _, err := net.SplitHostPort(host); err == nil {
		host = s
	}

	ips, err := f.GeoResolver.Resolver.LookupNetIP(context.Background(), "ip", host)
	if err != nil {
		return false
	}

	for _, ip := range ips {
		if ip.Is6() {
			return true
		}
	}

	return false
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

func (f *Functions) infile(line, filename string) bool {
	loader, _ := f.FileCache.LoadOrCompute(filename, func() *FileLoader[[]string] {
		return &FileLoader[[]string]{
			Filename: filename,
			Unmarshal: func(data []byte, v any) error {
				lines, ok := v.(*[]string)
				if !ok {
					return fmt.Errorf("*[]string required, found %T", v)
				}
				*lines = AppendSplitLines(make([]string, 0, strings.Count(b2s(data), "\n")), string(data))
				slices.Sort(*lines)
				return nil
			},
			PollDuration: 2 * time.Minute,
			Logger:       log.DefaultLogger.Slog(),
		}
	})
	if loader == nil {
		return false
	}

	lines := loader.Load()
	if lines == nil {
		return false
	}

	_, found := slices.BinarySearch(*lines, line)

	return found
}

func (f *Functions) infile2(line, filename1, filename2 string) bool {
	return f.infile(line, filename1) || f.infile(line, filename2)
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
