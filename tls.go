package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/phuslu/lru"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/valyala/bytebufferpool"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sys/cpu"
)

type TLSVersion uint16

var (
	TLSVersion13 TLSVersion = tls.VersionTLS13
	TLSVersion12 TLSVersion = tls.VersionTLS12
	TLSVersion11 TLSVersion = tls.VersionTLS11
	TLSVersion10 TLSVersion = tls.VersionTLS10
)

func (v TLSVersion) String() string {
	switch v {
	case TLSVersion13:
		return "TLSv1.3"
	case TLSVersion12:
		return "TLSv1.2"
	case TLSVersion11:
		return "TLSv1.1"
	case TLSVersion10:
		return "TLSv1.0"
	}
	return ""
}

type TLSConfiguratorEntry struct {
	ServerName     string
	KeyFile        string
	CertFile       string
	DisableHTTP2   bool
	DisableTLS11   bool
	PreferChacha20 bool
	DisableOCSP    bool
}

type TLSConfiguratorSniproxy struct {
	ServerName  string
	ProxyPass   string
	DialTimeout int
	Dialer      Dialer
}

type TLSConfigurator struct {
	DefaultServername string

	Entries          map[string]TLSConfiguratorEntry
	Sniproies        map[string]TLSConfiguratorSniproxy
	AutoCert         *autocert.Manager
	RootCA           *RootCA
	TLSConfigCache   *lru.TTLCache[string, *tls.Config]
	CertificateCache *lru.TTLCache[string, *tls.Certificate]
	ClientHelloMap   *xsync.MapOf[string, *tls.ClientHelloInfo]
}

func (m *TLSConfigurator) AddCertEntry(entry TLSConfiguratorEntry) error {
	if m.TLSConfigCache == nil {
		m.TLSConfigCache = lru.NewTTLCache[string, *tls.Config](1024)
	}

	if m.CertificateCache == nil {
		m.CertificateCache = lru.NewTTLCache[string, *tls.Certificate](1024)
	}

	if m.AutoCert == nil {
		m.AutoCert = &autocert.Manager{
			Cache:      autocert.DirCache("certs"),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: m.HostPolicy,
			ForceRSA:   false,
		}
	}

	if m.RootCA == nil {
		m.RootCA = &RootCA{
			DirName:    "certs",
			FileName:   "RootCA.crt",
			CommonName: "RootCA",
			Country:    "US",
			Province:   "California",
			Locality:   "Los Angeles",
			Duration:   3 * 365 * 24 * time.Hour,
			ForceRSA:   true,
		}
	}

	if net.ParseIP(entry.ServerName) != nil {
		if entry.KeyFile == "" {
			// a pure ip server name, generate a self-sign certificate
			m.RootCA.Issue(entry.ServerName)
			entry.KeyFile = filepath.Join(m.RootCA.DirName, entry.ServerName+".crt")
		}
	}

	if entry.KeyFile != "" && entry.CertFile == "" {
		entry.CertFile = entry.KeyFile
	}

	if m.Entries == nil {
		m.Entries = make(map[string]TLSConfiguratorEntry)
	}
	m.Entries[entry.ServerName] = entry

	return nil
}

func (m *TLSConfigurator) AddSniproxy(sniproxy TLSConfiguratorSniproxy) error {
	if m.Sniproies == nil {
		m.Sniproies = make(map[string]TLSConfiguratorSniproxy)
	}
	m.Sniproies[sniproxy.ServerName] = sniproxy

	return nil
}

func (m *TLSConfigurator) HostPolicy(ctx context.Context, host string) error {
	return nil
}

func (m *TLSConfigurator) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	entry, ok := m.Entries[hello.ServerName]
	if !ok {
		for key, value := range m.Entries {
			if key != "" && key[0] == '*' && strings.HasSuffix(hello.ServerName, key[1:]) {
				entry, ok = value, true
			}
		}
	}
	if !ok {
		return nil, errors.New("server_name(" + hello.ServerName + ") is not allowed")
	}

	hasTLS13, _ := LookupEcdsaCiphers(hello)

	if entry.KeyFile != "" {
		cacheKey := "cert:" + entry.ServerName
		if !hasTLS13 {
			cacheKey += "!tls13"
		}

		if v, _ := m.CertificateCache.Get(cacheKey); v != nil {
			return v, nil
		}

		certfile, keyfile := entry.CertFile, entry.KeyFile
		if !hasTLS13 {
			if _, err := os.Stat(certfile + "+rsa"); err == nil {
				certfile, keyfile = certfile+"+rsa", keyfile+"+rsa"
			}
		}
		cert, err := tls.LoadX509KeyPair(certfile, keyfile)
		if err != nil {
			return nil, err
		}

		m.CertificateCache.Set(cacheKey, &cert, 24*time.Hour)

		return &cert, nil
	}

	return m.AutoCert.GetCertificate(hello)
}

func (m *TLSConfigurator) GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	m.ClientHelloMap.Store(hello.Conn.RemoteAddr().String(), hello)

	if host, _, err := net.SplitHostPort(hello.ServerName); err == nil {
		hello.ServerName = host
	}

	if sni, ok := m.Sniproies[hello.ServerName]; ok {
		if mc, ok := hello.Conn.(*MirrorHeaderConn); ok {
			rconn, err := func(ctx context.Context) (net.Conn, error) {
				if sni.DialTimeout > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, time.Duration(sni.DialTimeout)*time.Second)
					defer cancel()
				}
				if !strings.Contains(sni.ProxyPass, "://") {
					return sni.Dialer.DialContext(ctx, "tcp", sni.ProxyPass)
				}
				u, err := url.Parse(sni.ProxyPass)
				if err != nil {
					return nil, err
				}
				switch u.Scheme {
				case "unix", "unixgram":
					return sni.Dialer.DialContext(ctx, u.Scheme, u.Path)
				default:
					return sni.Dialer.DialContext(ctx, u.Scheme, u.Host)
				}
			}(hello.Context())
			if err != nil {
				return nil, fmt.Errorf("sniproxy: proxy_pass %s error: %w", sni.ProxyPass, err)
			}
			_, err = rconn.Write(mc.Header.B)
			if err != nil {
				return nil, fmt.Errorf("sniproxy: proxy_pass %s error: %w", sni.ProxyPass, err)
			}
			go io.Copy(hello.Conn, rconn)
			_, err = io.Copy(rconn, hello.Conn)
			if err != nil {
				return nil, fmt.Errorf("sniproxy: proxy_pass %s error: %w", sni.ProxyPass, err)
			}
			return nil, io.EOF
		}
	}

	var serverName = hello.ServerName
	if serverName == "" {
		serverName = m.DefaultServername
	}

	var preferChacha20, disableTLS11, disableHTTP2, disableOCSP bool
	if entry, ok := m.Entries[hello.ServerName]; ok {
		preferChacha20 = entry.PreferChacha20
		disableHTTP2 = entry.DisableHTTP2
		disableTLS11 = entry.DisableTLS11
		disableOCSP = entry.DisableOCSP
	}

	hasAES := (cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ) || (cpu.ARM64.HasAES && cpu.ARM64.HasPMULL)
	hasTLS13, ecsdaCipher := LookupEcdsaCiphers(hello)
	hasChaCha20 := ecsdaCipher == tls.TLS_CHACHA20_POLY1305_SHA256

	if preferChacha20 && !hasChaCha20 && hasTLS13 {
		cs, i, j := hello.CipherSuites, 0, 2
		if IsTLSGreaseCode(cs[0]) {
			i, j = 1, 3
		}
		if len(cs) > j && cs[j] == tls.TLS_CHACHA20_POLY1305_SHA256 {
			cs[i], cs[j] = cs[j], cs[i]
			hasChaCha20 = true
		}
	}

	cacheKey := serverName
	if disableTLS11 {
		cacheKey += "!tls11"
	}
	if disableHTTP2 {
		cacheKey += "!h2"
	}
	if disableOCSP {
		cacheKey += "!ocsp"
	}
	if !hasAES {
		cacheKey += "!aes"
	}
	if !hasTLS13 {
		cacheKey += "!tls13"
	}
	if ecsdaCipher == 0 {
		cacheKey += "!ecdsa"
	}
	if hasChaCha20 {
		cacheKey += ":chacha20"
	}

	if v, _ := m.TLSConfigCache.Get(cacheKey); v != nil {
		return v, nil
	}

	cert, err := m.GetCertificate(hello)
	if err != nil {
		return nil, err
	}

	cacert := cert.Leaf
	if n := len(cert.Certificate); cacert == nil && n >= 2 {
		cacert, _ = x509.ParseCertificate(cert.Certificate[n-2])
	}

	if !disableOCSP {
		cert.OCSPStaple, err = GetOCSPStaple(hello.Context(), http.DefaultTransport, cacert)
		if err != nil {
			// log error
		}
	}

	config := &tls.Config{
		MaxVersion:               tls.VersionTLS13,
		MinVersion:               tls.VersionTLS10,
		Certificates:             []tls.Certificate{*cert},
		PreferServerCipherSuites: true,
		NextProtos:               []string{"h2", "http/1.1", "acme-tls/1"},
	}

	if disableTLS11 {
		config.MinVersion = tls.VersionTLS12
	}

	if disableHTTP2 {
		config.NextProtos = []string{"http/1.1", "acme-tls/1"}
	}

	if !hasTLS13 {
		config.MaxVersion = tls.VersionTLS12
	}

	if hasChaCha20 {
		config.PreferServerCipherSuites = false
	}

	m.TLSConfigCache.Set(cacheKey, config, 24*time.Hour)

	return config, nil
}

func (m *TLSConfigurator) ConnState(c net.Conn, cs http.ConnState) {
	switch cs {
	case http.StateHijacked, http.StateClosed:
		if header := GetMirrorHeader(c); header != nil {
			bytebufferpool.Put(header)
		}
		m.ClientHelloMap.Delete(c.RemoteAddr().String())
	}
}
