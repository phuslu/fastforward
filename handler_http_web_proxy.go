package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"text/template"

	"github.com/phuslu/log"
	"golang.org/x/crypto/cryptobyte"
)

type HTTPWebProxyHandler struct {
	Transport         *http.Transport
	Functions         template.FuncMap
	Pass              string
	AuthBasic         string
	AuthBasicUserFile string
	SetHeaders        string
	DumpFailure       bool

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
	ri := GetRequestInfo(req)

	// if req.Method == http.MethodConnect {
	// 	RejectRequest(rw, req)
	// 	return
	// }

	if h.AuthBasicUserFile != "" {
		if err := HtpasswdVerify(h.AuthBasicUserFile, req); err != nil && !os.IsNotExist(err) {
			log.Error().Context(ri.LogContext).Err(err).Msg("web dav auth error")
			rw.Header().Set("www-authenticate", `Basic realm="`+h.AuthBasic+`"`)
			http.Error(rw, "401 unauthorised: "+err.Error(), http.StatusUnauthorized)

			return
		}
	}

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
	// req.Host = u.Host

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
		req.Header.Set("x-forwarded-ssl", "on")
		req.Header.Set("x-url-scheme", "https")
		req.Header.Set("x-http-proto", req.Proto)
		req.Header.Set("x-ja3-fingerprint", getTlsFingerprint(ri.TLSVersion, ri.ClientHelloInfo, ri.ClientHelloRaw))
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

func getTlsFingerprint(version TLSVersion, info *tls.ClientHelloInfo, raw []byte) string {
	var sb strings.Builder

	// version
	fmt.Fprintf(&sb, "%d,", version)

	// ciphers
	i := 0
	for _, c := range info.CipherSuites {
		if IsTLSGreaseCode(c) {
			continue
		}
		if i > 0 {
			sb.WriteByte('-')
		}
		fmt.Fprintf(&sb, "%d", c)
		i++
	}
	sb.WriteByte(',')

	if exts, err := getTlsExtensions(raw); err == nil {
		i = 0
		for _, c := range exts {
			if IsTLSGreaseCode(c) || c == 0x0015 {
				continue
			}
			if i > 0 {
				sb.WriteByte('-')
			}
			fmt.Fprintf(&sb, "%d", c)
			i++
		}
	}
	sb.WriteByte(',')

	// groups
	i = 0
	for _, c := range info.SupportedCurves {
		if IsTLSGreaseCode(uint16(c)) {
			continue
		}
		if i > 0 {
			sb.WriteByte('-')
		}
		fmt.Fprintf(&sb, "%d", c)
		i++
	}
	sb.WriteByte(',')

	// formats
	for i, c := range info.SupportedPoints {
		if i > 0 {
			sb.WriteByte('-')
		}
		fmt.Fprintf(&sb, "%d", c)
	}

	return sb.String()
}

// from https://github.com/Jigsaw-Code/getsni
func getTlsExtensions(clienthello []byte) ([]uint16, error) {
	if len(clienthello) == 0 {
		return nil, errors.New("Bad TLSClientHello")
	}

	plaintext := cryptobyte.String(clienthello)

	var s cryptobyte.String
	// Skip uint8 ContentType and uint16 ProtocolVersion
	if !plaintext.Skip(1+2) || !plaintext.ReadUint16LengthPrefixed(&s) {
		return nil, errors.New("Bad TLSPlaintext")
	}

	// Skip uint8 message type, uint24 length, uint16 version, and 32 byte random.
	var sessionID cryptobyte.String
	if !s.Skip(1+3+2+32) ||
		!s.ReadUint8LengthPrefixed(&sessionID) {
		return nil, errors.New("Bad Handshake message")
	}

	var cipherSuites cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&cipherSuites) {
		return nil, errors.New("Bad ciphersuites")
	}

	var compressionMethods cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&compressionMethods) {
		return nil, errors.New("Bad compression methods")
	}

	if s.Empty() {
		// ClientHello is optionally followed by extension data
		return nil, errors.New("Short hello")
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return nil, errors.New("Bad extensions")
	}

	exts := []uint16{}
	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return nil, errors.New("Bad extension")
		}
		exts = append(exts, extension)
	}

	if len(exts) == 0 {
		return nil, errors.New("No Extensions")
	}

	return exts, nil
}
