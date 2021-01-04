package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"text/template"

	"github.com/phuslu/log"
)

type HTTPWebProxyHandler struct {
	Transport   *http.Transport
	Functions   template.FuncMap
	Pass        string
	SetHeaders  string
	DumpFailure bool

	upstream *template.Template
	headers  *template.Template
}

func (h *HTTPWebProxyHandler) Load() error {
	var err error

	h.upstream, err = template.New(h.Pass).Funcs(h.Functions).Parse(h.Pass)
	if err != nil {
		return err
	}

	h.headers, err = template.New(h.SetHeaders).Funcs(h.Functions).Parse(h.SetHeaders)
	if err != nil {
		return err
	}

	return nil
}

func (h *HTTPWebProxyHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	ri := req.Context().Value(RequestInfoContextKey).(*RequestInfo)

	// if req.Method == http.MethodConnect {
	// 	RejectRequest(rw, req)
	// 	return
	// }

	var sb strings.Builder
	h.upstream.Execute(&sb, struct {
		Request *http.Request
	}{req})

	u, err := url.Parse(sb.String())
	if err != nil {
		http.Error(rw, fmt.Sprintf("bad upstream %+v", sb.String()), http.StatusServiceUnavailable)
		return
	}

	if u.Scheme == "file" {
		http.Error(rw, "use index_root instead of file://", http.StatusServiceUnavailable)
		return
	}

	var tr http.RoundTripper = h.Transport

	req.URL.Scheme = u.Scheme
	req.URL.Host = u.Host

	if s := req.Header.Get("x-forwarded-for"); s != "" {
		req.Header.Set("x-forwarded-for", s+", "+ri.RemoteIP)
	} else {
		req.Header.Set("x-forwarded-for", ri.RemoteIP)
	}

	if !IsReservedIP(net.ParseIP(ri.RemoteIP)) {
		req.Header.Set("x-real-ip", ri.RemoteIP)
	}

	if ri.TLSVersion != 0 {
		req.Header.Set("x-forwarded-proto", "https")
		req.Header.Set("x-tls-version", ri.TLSVersion.String())
	}
	h.setHeaders(req)

	if req.ProtoAtLeast(3, 0) && req.Method == http.MethodGet {
		req.Body = nil
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		if h.upstream != nil {
			log.Warn().Err(err).Context(ri.LogContext).Msg("upstream error")
			if IsTimeout(err) {
				http.Error(rw, "504 Gateway Timeout", http.StatusGatewayTimeout)
			} else {
				http.Error(rw, "502 Bad Gateway", http.StatusBadGateway)
			}
		} else {
			http.NotFound(rw, req)
		}
		return
	}

	log.Info().Context(ri.LogContext).Int("http_status", resp.StatusCode).Int64("http_content_length", resp.ContentLength).Msg("proxy_pass request")

	if req.ProtoAtLeast(2, 0) {
		resp.Header.Del("connection")
		resp.Header.Del("keep-alive")
	}

	// if req.ProtoMajor != 2 && req.TLS != nil && req.TLS.Version == tls.VersionTLS13 {
	// 	_, port, _ := net.SplitHostPort(ri.ServerAddr)
	// 	resp.Header.Set("alt-svc", fmt.Sprintf(`%s=":%s"; ma=86400`, nextProtoH3, port))
	// }

	if h.DumpFailure && resp.StatusCode >= http.StatusBadRequest {
		data, err := httputil.DumpResponse(resp, true)
		if err != nil {
			log.Warn().Err(err).Context(ri.LogContext).Int("status", resp.StatusCode).Int64("content_length", resp.ContentLength).Msg("DumpFailureResponse error")
		} else {
			log.Info().Context(ri.LogContext).Int("status", resp.StatusCode).Int64("content_length", resp.ContentLength).Str("data", string(data)).Msg("DumpFailureResponse ok")
		}
	}

	if resp.StatusCode == http.StatusSwitchingProtocols {
		var w io.Writer
		var r io.Reader

		conn, ok := resp.Body.(io.ReadWriteCloser)
		if !ok {
			http.Error(rw, fmt.Sprintf("internal error: 101 switching protocols response with non-writable body"), 500)
			return
		}
		defer conn.Close()

		for k, vv := range resp.Header {
			for _, v := range vv {
				rw.Header().Add(k, v)
			}
		}
		rw.WriteHeader(resp.StatusCode)

		if req.ProtoAtLeast(2, 0) {
			flusher, ok := rw.(http.Flusher)
			if !ok {
				http.Error(rw, fmt.Sprintf("%#v is not http.Flusher", rw), http.StatusBadGateway)
				return
			}
			flusher.Flush()

			w = FlushWriter{rw}
			r = req.Body
		} else {
			hijacker, ok := rw.(http.Hijacker)
			if !ok {
				http.Error(rw, fmt.Sprintf("%#v is not http.Hijacker", rw), http.StatusBadGateway)
				return
			}
			lconn, flusher, err := hijacker.Hijack()
			if err != nil {
				http.Error(rw, err.Error(), http.StatusBadGateway)
				return
			}
			defer lconn.Close()
			if err := flusher.Flush(); err != nil {
				http.Error(rw, fmt.Sprintf("response flush: %v", err), 500)
				return
			}

			w = lconn
			r = lconn
		}

		go io.Copy(w, conn)
		io.Copy(conn, r)
	} else {
		for key, values := range resp.Header {
			for _, value := range values {
				rw.Header().Add(key, value)
			}
		}
		rw.WriteHeader(resp.StatusCode)
		defer resp.Body.Close()
		io.Copy(rw, resp.Body)
	}
}

func (h *HTTPWebProxyHandler) setHeaders(req *http.Request) {
	if h.SetHeaders == "" {
		return
	}

	var sb strings.Builder
	h.headers.Execute(&sb, struct {
		Request *http.Request
	}{req})

	for _, line := range strings.Split(sb.String(), "\n") {
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		key, value := parts[0], strings.TrimSpace(parts[1])
		switch strings.ToLower(key) {
		case "host":
			req.URL.Host = value
			req.Host = value
		default:
			req.Header.Set(key, value)
		}
	}
}
