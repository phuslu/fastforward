package main

import (
	"encoding/base64"
	"io/ioutil"
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
	cache    *shardmap.Map
}

func (h *HTTPDoHHandler) Load() (err error) {
	h.upstream, err = url.Parse(h.Config.Doh.Upstream)
	h.cache = shardmap.New(0)
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

	var name, typ, ct string
	qa := req.URL.Query()
	ct = qa.Get("ct")
	if ct == "" {
		ct = req.Header.Get("content-type")
	}
	switch ct {
	case "application/dns-json":
		name, typ = qa.Get("name"), qa.Get("type")
	default:
		var data []byte
		var err error
		switch req.Method {
		case http.MethodGet:
			data, err = base64.URLEncoding.DecodeString(qa.Get("dns"))
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
		name = msg.Questions[0].Name.String()
		switch msg.Questions[0].Type {
		case dnsmessage.TypeA:
			typ = "A"
		case dnsmessage.TypeAAAA:
			typ = "AAAA"
		}
	}

	log.Info().Context(ri.LogContext).Str("name", name).Str("type", typ).Str("content_type", ct).Msg("doh request")

	// hit cache?
	cacheKey := name + typ + ct
	v, ok := h.cache.Get(cacheKey)
	if ok {
		item := v.(DoHCacheItem)
		if timeNow().Sub(item.Time) < 10*time.Minute {
			rw.Header().Set("content-type", ct)
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

	data, err := ioutil.ReadAll(resp.Body)
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
