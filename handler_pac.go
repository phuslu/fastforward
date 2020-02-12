package main

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/phuslu/log"
	"github.com/tidwall/shardmap"
	"golang.org/x/sync/singleflight"
)

const (
	DefaultPacIPlist = "https://cdn.jsdelivr.net/gh/17mon/china_ip_list@master/china_ip_list.txt"
)

type PacHandler struct {
	Next   http.Handler
	Config HTTPConfig

	PacIPList    string
	singleflight *singleflight.Group
	cache        *shardmap.Map
}

type PacCacheItem struct {
	Deadline time.Time
	Data     []byte
}

func (h *PacHandler) Load() error {
	if !h.Config.PacEnabled {
		return nil
	}

	h.PacIPList = h.Config.PacIplist
	if h.PacIPList == "" {
		h.PacIPList = DefaultPacIPlist
	}

	h.singleflight = &singleflight.Group{}
	h.cache = shardmap.New(0)

	return nil
}

func (h *PacHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(RequestInfo)

	if req.TLS != nil {
		if !(req.ProtoAtLeast(2, 0) && ri.TLSVersion == tls.VersionTLS13 && IsTLSGreaseCode(ri.ClientHelloInfo.CipherSuites[0])) {
			h.Next.ServeHTTP(rw, req)
			return
		}
	}

	if !h.Config.PacEnabled || !strings.HasSuffix(req.URL.Path, ".pac") {
		h.Next.ServeHTTP(rw, req)
		return
	}

	hasGzip := strings.Contains(req.Header.Get("accept-encoding"), "gzip")

	log.Info().Str("server_name", ri.ServerName).Str("server_addr", ri.ServerAddr).Str("tls_version", ri.TLSVersion.String()).Str("remote_ip", ri.RemoteIP).Str("http_method", req.Method).Str("http_url", req.URL.String()).Str("http_proto", req.Proto).Str("user_agent", req.UserAgent()).Msg("pac request")

	var pac []byte
	var pacCacheKey = req.Host + req.URL.Path + h.PacIPList
	if !hasGzip {
		pacCacheKey += "!gzip"
	}

	if v, ok := h.cache.Get(pacCacheKey); ok && v.(PacCacheItem).Deadline.After(timeNow()) {
		pac = v.(PacCacheItem).Data
	} else {
		h.cache.Delete(pacCacheKey)
		v, err, _ := h.singleflight.Do(h.PacIPList, func() (interface{}, error) {
			return ReadFile(h.PacIPList)
		})
		if err != nil {
			log.Warn().Err(err).Str("server_name", ri.ServerName).Str("server_addr", ri.ServerAddr).Str("remote_ip", ri.RemoteIP).Str("http_method", req.Method).Str("http_url", req.URL.String()).Str("http_proto", req.Proto).Str("pac_ip_list", h.PacIPList).Msg("read pac iplist error")
			http.Error(rw, err.Error(), http.StatusServiceUnavailable)
			return
		}

		body := v.([]byte)

		iplist, err := MergeCIDRToIPList(bytes.NewReader(body))
		if err != nil {
			log.Warn().Err(err).Str("server_name", ri.ServerName).Str("server_addr", ri.ServerAddr).Str("remote_ip", ri.RemoteIP).Str("http_method", req.Method).Str("http_url", req.URL.String()).Str("http_proto", req.Proto).Str("rule_url", h.PacIPList).Msg("parse pac file error")
			http.Error(rw, err.Error(), http.StatusServiceUnavailable)
			return
		}

		pac, err = h.generatePac(req, iplist)
		if err != nil {
			log.Warn().Err(err).Str("server_name", ri.ServerName).Str("server_addr", ri.ServerAddr).Str("remote_ip", ri.RemoteIP).Str("http_method", req.Method).Str("http_url", req.URL.String()).Str("http_proto", req.Proto).Str("rule_url", h.PacIPList).Msg("generate pac file error")
			if os.IsNotExist(err) {
				h.Next.ServeHTTP(rw, req)
			} else {
				http.Error(rw, err.Error(), http.StatusServiceUnavailable)
			}
			return
		}

		if hasGzip {
			b := new(bytes.Buffer)
			w := gzip.NewWriter(b)
			w.Write(pac)
			w.Close()
			pac = b.Bytes()
		}

		h.cache.Set(pacCacheKey, PacCacheItem{Deadline: timeNow().Add(12 * time.Hour), Data: pac})
		h.singleflight.Forget(h.PacIPList)
	}

	rw.Header().Add("cache-control", "max-age=86400")
	rw.Header().Add("content-type", "text/plain; charset=UTF-8")
	rw.Header().Add("content-length", strconv.FormatUint(uint64(len(pac)), 10))
	if hasGzip {
		rw.Header().Add("content-encoding", "gzip")
	}
	rw.WriteHeader(http.StatusOK)
	rw.Write(pac)
}

func (h *PacHandler) generatePac(req *http.Request, iplist []IPInt) ([]byte, error) {
	data, err := ioutil.ReadFile(req.URL.Path[1:])
	if err != nil {
		return nil, err
	}

	tmpl, err := template.New(req.URL.Path[1:]).Parse(string(data))
	if err != nil {
		return nil, err
	}

	var proxyScheme, proxyHost, proxyPort string

	if req.TLS != nil {
		proxyScheme = "HTTPS"
		proxyPort = "443"
	} else {
		proxyScheme = "PROXY"
		proxyPort = "80"
	}

	if _, _, err := net.SplitHostPort(req.Host); err == nil {
		proxyHost = req.Host
	} else {
		proxyHost = req.Host + ":" + proxyPort
	}

	var b bytes.Buffer
	err = tmpl.Execute(&b, struct {
		Version   string
		UpdatedAt time.Time
		Scheme    string
		Host      string
		IPList    PacIPList
	}{
		Version:   version,
		UpdatedAt: timeNow(),
		Scheme:    proxyScheme,
		Host:      proxyHost,
		IPList:    PacIPList(iplist),
	})
	if err != nil {
		return nil, err
	}

	return b.Bytes(), nil
}

type PacIPList []IPInt

func (iplist PacIPList) EndToStep() PacIPList {
	iplist2 := make(PacIPList, len(iplist))
	for i := range iplist {
		if i%2 == 0 {
			iplist2[i] = iplist[i]
		} else {
			iplist2[i] = iplist[i] - iplist[i-1]
		}
	}
	return iplist2
}
