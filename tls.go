package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"path/filepath"
	"time"

	"github.com/tidwall/shardmap"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/sys/cpu"
)

type TLSConfiguratorEntry struct {
	ServerName     string
	KeyFile        string
	CertFile       string
	DisableHTTP2   bool
	PreferChacha20 bool
}

type TLSConfigurator struct {
	DefaultServername      string
	AllowUnknownServerName bool

	Entries          map[string]TLSConfiguratorEntry
	AutoCert         *autocert.Manager
	RootCA           *RootCA
	ConfigCache      *shardmap.Map
	CertCache        *shardmap.Map
	ClientHelloCache *shardmap.Map
}

type TLSConfigCacheItem struct {
	Config *tls.Config

	expires int64
}

type TLSCertCacheItem struct {
	Certificate *tls.Certificate

	expires int64
}

func (m *TLSConfigurator) AddCertEntry(entry TLSConfiguratorEntry) error {
	if m.Entries == nil {
		m.Entries = make(map[string]TLSConfiguratorEntry)
	}

	if m.ConfigCache == nil {
		m.ConfigCache = shardmap.New(0)
	}

	if m.CertCache == nil {
		m.CertCache = shardmap.New(0)
	}

	if m.ClientHelloCache == nil {
		m.ClientHelloCache = shardmap.New(0)
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

	m.Entries[entry.ServerName] = entry

	return nil
}

func (m *TLSConfigurator) HostPolicy(ctx context.Context, host string) error {
	return nil
}

func (m *TLSConfigurator) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	entry, ok := m.Entries[hello.ServerName]
	if !ok {
		if !m.AllowUnknownServerName {
			return nil, errors.New("server_name(" + hello.ServerName + ") is not allowed")
		}
	}

	if entry.KeyFile != "" {
		cacheKey := "cert:" + entry.ServerName

		if v, ok := m.CertCache.Get(cacheKey); ok {
			item := v.(TLSCertCacheItem)
			if item.expires > unix() {
				return item.Certificate, nil
			}
			m.CertCache.Delete(cacheKey)
		}

		cert, err := tls.LoadX509KeyPair(entry.CertFile, entry.KeyFile)
		if err != nil {
			return nil, err
		}

		m.CertCache.Set(cacheKey, TLSCertCacheItem{&cert, unix() + 24*3600})

		return &cert, nil
	}

	return m.AutoCert.GetCertificate(hello)
}

func (m *TLSConfigurator) GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	m.ClientHelloCache.Set(hello.Conn.RemoteAddr().String(), hello)

	if host, _, err := net.SplitHostPort(hello.ServerName); err == nil {
		hello.ServerName = host
	}

	var serverName = hello.ServerName
	if serverName == "" {
		serverName = m.DefaultServername
	}

	var preferChacha20, disableHTTP2 bool
	if entry, ok := m.Entries[hello.ServerName]; ok {
		preferChacha20 = entry.PreferChacha20
		disableHTTP2 = entry.DisableHTTP2
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
	if disableHTTP2 {
		cacheKey += "!h2"
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

	if v, ok := m.ConfigCache.Get(cacheKey); ok {
		item := v.(TLSConfigCacheItem)
		if item.expires > unix() {
			return item.Config, nil
		}
		m.ConfigCache.Delete(cacheKey)
	}

	cert, err := m.GetCertificate(hello)
	if err != nil {
		return nil, err
	}

	cert.OCSPStaple, err = GetOCSPStaple(cert.Leaf)
	if err != nil {
		// log error
	}

	config := &tls.Config{
		MaxVersion:               tls.VersionTLS13,
		MinVersion:               tls.VersionTLS10,
		Certificates:             []tls.Certificate{*cert},
		PreferServerCipherSuites: true,
		NextProtos:               []string{"h2", "http/1.1", "acme-tls/1"},
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

	m.ConfigCache.Set(cacheKey, TLSConfigCacheItem{config, unix() + 72*3600})

	return config, nil
}

func (m *TLSConfigurator) ConnState(c net.Conn, cs http.ConnState) {
	switch cs {
	case http.StateHijacked, http.StateClosed:
		m.ClientHelloCache.Delete(c.RemoteAddr().String())
	}
}
