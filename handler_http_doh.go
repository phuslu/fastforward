package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/phuslu/log"
	"github.com/tidwall/shardmap"
	"golang.org/x/net/dns/dnsmessage"
)

type HTTPDoHHandler struct {
	Next      http.Handler
	Config    HTTPConfig
	Transport *http.Transport

	upstream *url.URL
	prelude  map[string][]dnsmessage.Resource
	cache    *shardmap.Map
}

func (h *HTTPDoHHandler) Load() (err error) {
	h.upstream, err = url.Parse(h.Config.Doh.Upstream)
	h.cache = shardmap.New(0)

	// prelude to cache
	h.prelude = make(map[string][]dnsmessage.Resource)
	for name, iplist := range h.Config.Doh.Prelude {
		for _, typ := range []string{"A", "AAAA"} {
			key := name + typ
			if _, ok := h.prelude[key]; !ok {
				h.prelude[key] = make([]dnsmessage.Resource, 0)
			}
			for _, s := range iplist {
				ip := net.ParseIP(s)
				if ip == nil {
					return fmt.Errorf("invalid prelude ip: %+v", s)
				}
				ip4 := ip.To4()
				switch {
				case ip4 != nil && typ == "A":
					h.prelude[key] = append(h.prelude[key], dnsmessage.Resource{
						dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName(name),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
							TTL:   600,
						},
						&dnsmessage.AResource{[4]byte{
							ip4[0], ip4[1], ip4[2], ip4[3],
						}},
					})
				case ip4 == nil && typ == "AAAA":
					h.prelude[key] = append(h.prelude[key], dnsmessage.Resource{
						dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName(name),
							Type:  dnsmessage.TypeAAAA,
							Class: dnsmessage.ClassINET,
							TTL:   600,
						},
						&dnsmessage.AAAAResource{[16]byte{
							ip[0], ip[1], ip[2], ip[3],
							ip[4], ip[5], ip[6], ip[7],
							ip[8], ip[9], ip[10], ip[11],
							ip[12], ip[13], ip[14], ip[15],
						}},
					})
				}
			}
		}
	}

	return
}

type DoHCacheItem struct {
	Time time.Time
	Data []byte
}

func (h *HTTPDoHHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	if req.TLS == nil {
		h.Next.ServeHTTP(rw, req)
		return
	}

	if !h.Config.Doh.Enabled || req.URL.Path != h.Config.Doh.Path {
		h.Next.ServeHTTP(rw, req)
		return
	}

	if req.Header.Get("content-type") == "application/dns-json" ||
		req.URL.Query().Get("ct") == "application/dns-json" {
		req.Host = h.upstream.Host
		req.URL.Host = h.upstream.Host
		req.URL.Path = h.upstream.Path
		req.URL.Scheme = h.upstream.Scheme
		resp, err := h.Transport.RoundTrip(req)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for key, values := range resp.Header {
			for _, value := range values {
				rw.Header().Add(key, value)
			}
		}
		rw.WriteHeader(resp.StatusCode)
		io.Copy(rw, resp.Body)
		return
	}

	var data []byte
	var err error
	switch req.Method {
	case http.MethodGet:
		data, err = base64.URLEncoding.DecodeString(req.URL.Query().Get("dns"))
	default:
		data, err = ioutil.ReadAll(req.Body)
	}
	if err != nil {
		log.Error().Err(err).Context(ri.LogContext).Msg("doh read body error")
		return
	}
	var msg dnsmessage.Message
	err = msg.Unpack(data)
	if err != nil {
		log.Error().Err(err).Context(ri.LogContext).Msg("doh parse body error")
		return
	}
	if len(msg.Questions) != 1 {
		log.Error().Context(ri.LogContext).Msg("doh request body error")
	}
	name := msg.Questions[0].Name.String()
	typ := msg.Questions[0].Type.String()

	log.Info().Context(ri.LogContext).Str("name", name).Str("type", typ).Msg("doh request")

	cacheKey := name + typ

	// prelude?
	if answers, ok := h.prelude[cacheKey]; ok {
		msg.Answers = answers
		body, err := msg.Pack()
		if err != nil {
			log.Error().Err(err).Context(ri.LogContext).Msg("doh parse body error")
			return
		}
		rw.Header().Set("content-type", "application/dns-message")
		rw.WriteHeader(http.StatusOK)
		rw.Write(body)
		return
	}

	// hit cache?
	v, ok := h.cache.Get(cacheKey)
	if ok {
		item := v.(DoHCacheItem)
		if timeNow().Sub(item.Time) < 10*time.Minute {
			rw.Header().Set("content-type", "application/dns-message")
			rw.WriteHeader(http.StatusOK)
			rw.Write(item.Data)
			return
		}
		h.cache.Delete(cacheKey)
	}

	req.Host = h.upstream.Host
	req.URL.Host = h.upstream.Host
	req.URL.Path = h.upstream.Path
	req.URL.Scheme = h.upstream.Scheme
	resp, err := h.Transport.RoundTrip(req)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	data, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusBadGateway)
		return
	}

	for key, values := range resp.Header {
		switch strings.ToLower(key) {
		case "server", "expect-ct", "cf-ray", "cf-request-id":
			continue
		}
		for _, value := range values {
			rw.Header().Add(key, value)
		}
	}
	rw.WriteHeader(resp.StatusCode)
	rw.Write(data)

	// update cache
	if resp.StatusCode == http.StatusOK {
		h.cache.Set(cacheKey, DoHCacheItem{time.Now(), data})
	}
}
