package main

import (
	"cmp"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mileusna/useragent"
	"github.com/oschwald/maxminddb-golang"
	"github.com/phuslu/fastdns"
	"github.com/phuslu/geosite"
	"github.com/phuslu/log"
	"github.com/phuslu/lru"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/robfig/cron/v3"
	"golang.org/x/net/http2"
)

var (
	version = "1984"
	timeNow = time.Now

	DefaultUserAgent = "Liner/" + version
	ChromeUserAgent  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)

func main() {
	executable, err := os.Executable()
	if err != nil {
		println("cannot get executable path")
		os.Exit(1)
	}

	os.Chdir(filepath.Dir(executable))

	if len(os.Args) > 1 && os.Args[1] == "-version" {
		println(version)
		return
	}

	filename := ""
	if len(os.Args) > 1 {
		filename = os.Args[1]
	}
	config, err := NewConfig(filename)
	if err != nil {
		log.Fatal().Err(err).Str("filename", filename).Msg("NewConfig() error")
		os.Exit(1)
	}

	// main logger
	var forwardLogger log.Logger
	if log.IsTerminal(os.Stderr.Fd()) {
		log.DefaultLogger = log.Logger{
			Level:      log.ParseLevel(cmp.Or(config.Global.LogLevel, "info")),
			Caller:     1,
			TimeFormat: "15:04:05",
			Writer: &log.ConsoleWriter{
				ColorOutput:    true,
				EndWithMessage: true,
			},
		}
		forwardLogger = log.Logger{
			Level:  log.ParseLevel(cmp.Or(config.Global.LogLevel, "info")),
			Writer: log.DefaultLogger.Writer,
		}
	} else {
		// main logger
		log.DefaultLogger = log.Logger{
			Level:  log.ParseLevel(cmp.Or(config.Global.LogLevel, "info")),
			Caller: 1,
			Writer: &log.FileWriter{
				Filename:   executable + ".log",
				MaxBackups: 1,
				MaxSize:    cmp.Or(config.Global.LogMaxsize, 10*1024*1024),
				LocalTime:  config.Global.LogLocaltime,
			},
		}
		// forward logger
		forwardLogger = log.Logger{
			Level: log.ParseLevel(cmp.Or(config.Global.LogLevel, "info")),
			Writer: &log.AsyncWriter{
				ChannelSize: 8192,
				Writer: &log.FileWriter{
					Filename:   "forward.log",
					MaxBackups: cmp.Or(config.Global.LogBackups, 2),
					MaxSize:    cmp.Or(config.Global.LogMaxsize, 20*1024*1024),
					LocalTime:  config.Global.LogLocaltime,
				},
			},
		}
	}

	slog.SetDefault(log.DefaultLogger.Slog())

	// resolver factory
	resolvers := map[string]*Resolver{}
	resolverof := func(addr string) *Resolver {
		r, _ := resolvers[addr]
		if r != nil {
			return r
		}
		r = &Resolver{
			Client: &fastdns.Client{
				Addr: addr,
			},
			CacheDuration: 10 * time.Minute,
			LRUCache:      lru.NewTTLCache[string, []netip.Addr](max(config.Global.DnsCacheSize, 64*1024)),
		}
		if config.Global.DnsCacheDuration != "" {
			dur, err := time.ParseDuration(config.Global.DnsCacheDuration)
			if dur == 0 || err != nil {
				log.Fatal().Err(err).Str("dns_cache_duration", config.Global.DnsCacheDuration).Msg("invalid dns_cache_duration")
			}
			r.CacheDuration = dur
		}
		switch {
		case addr == "":
			log.Fatal().Str("addr", addr).Msg("invalid dns_server addr")
		case strings.Contains(addr, "://"):
			u, err := url.Parse(addr)
			if err != nil {
				log.Fatal().Err(err).Str("dns_server", addr).Msg("parse dns_server error")
			}
			switch u.Scheme {
			case "https", "http2", "h2", "doh":
				u.Scheme = "https"
				r.Client.Dialer = &fastdns.HTTPDialer{
					Endpoint: u,
					Header: http.Header{
						"content-type": {"application/dns-message"},
						"user-agent":   {cmp.Or(u.Query().Get("user_agent"), DefaultUserAgent)},
					},
					Transport: &http2.Transport{
						TLSClientConfig: &tls.Config{
							ServerName:         u.Hostname(),
							ClientSessionCache: tls.NewLRUClientSessionCache(128),
						},
					},
				}
			case "http3", "h3", "doh3":
				u.Scheme = "https"
				r.Client.Dialer = &fastdns.HTTPDialer{
					Endpoint: u,
					Header: http.Header{
						"content-type": {"application/dns-message"},
						"user-agent":   {cmp.Or(u.Query().Get("user_agent"), DefaultUserAgent)},
					},
					Transport: &http3.Transport{
						DisableCompression: false,
						EnableDatagrams:    true,
						TLSClientConfig: &tls.Config{
							NextProtos:         []string{"h3"},
							InsecureSkipVerify: u.Query().Get("insecure") == "true",
							ServerName:         u.Hostname(),
							ClientSessionCache: tls.NewLRUClientSessionCache(128),
						},
						QUICConfig: &quic.Config{
							DisablePathMTUDiscovery: false,
							EnableDatagrams:         true,
							MaxIncomingUniStreams:   200,
							MaxIncomingStreams:      200,
						},
					},
				}
			default:
				log.Fatal().Strs("support protocols", []string{"udp", "https", "http2", "http3"}).Msg("parse dns_server error")
			}
		default:
			host := addr
			if _, _, err := net.SplitHostPort(host); err != nil {
				host = net.JoinHostPort(host, "53")
			}
			u, err := net.ResolveUDPAddr("udp", host)
			if err != nil {
				log.Fatal().Str("addr", addr).Msg("invalid dns_server addr")
			}
			r.Client.Dialer = &fastdns.UDPDialer{
				Addr:     u,
				Timeout:  3 * time.Second,
				MaxConns: 128,
			}
		}

		resolvers[addr] = r
		return r
	}

	// global resolver with geo support
	if config.Global.DnsServer == "" {
		if data, err := os.ReadFile("/etc/resolv.conf"); err == nil {
			if m := regexp.MustCompile(`(^|\n)\s*nameserver\s+(\S+)`).FindAllStringSubmatch(string(data), -1); len(m) != 0 {
				config.Global.DnsServer = cmp.Or(m[0][2], "https://1.1.1.1/dns-query")
			}
		}
	}
	geoResolver := &GeoResolver{
		Resolver:      resolverof(config.Global.DnsServer),
		LocalizedName: true,
	}
	for _, name := range []string{"GeoIP2-City.mmdb", "GeoLite2-City.mmdb"} {
		geoResolver.CityReader, err = maxminddb.Open(name)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Fatal().Err(err).Str("geoip2_city_database", name).Msg("load geoip2 city database error")
		}
		break
	}
	for _, name := range []string{"GeoIP2-ISP.mmdb", "GeoLite2-ISP.mmdb"} {
		geoResolver.ISPReader, err = maxminddb.Open(name)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Fatal().Err(err).Str("geoip2_isp_database", name).Msg("load geoip2 isp database error")
		}
		break
	}
	for _, name := range []string{"GeoIP2-Domain.mmdb", "GeoLite2-Domain.mmdb"} {
		geoResolver.DomainReader, err = maxminddb.Open(name)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Fatal().Err(err).Str("geoip2_domain_database", name).Msg("load geoip2 domain database error")
		}
		break
	}
	for _, name := range []string{"GeoIP2-Connection-Type.mmdb", "GeoLite2-Connection-Type.mmdb"} {
		geoResolver.ConnectionTypeReader, err = maxminddb.Open(name)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Fatal().Err(err).Str("geoip2_connection_type_database", name).Msg("load geoip2 connection_type database error")
		}
		break
	}

	// global dialer
	dialer := &LocalDialer{
		Resolver:        geoResolver.Resolver,
		ResolveCache:    lru.NewTTLCache[string, []netip.Addr](8192),
		Concurrency:     2,
		PerferIPv6:      false,
		ForbidLocalAddr: config.Global.ForbidLocalAddr,
		ReadBuffSize:    config.Global.DialReadBuffer,
		WriteBuffSize:   config.Global.DialWriteBuffer,
		DialTimeout:     time.Duration(cmp.Or(config.Global.DialTimeout, 30)) * time.Second,
		TCPKeepAlive:    30 * time.Second,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: tls.NewLRUClientSessionCache(2048),
		},
	}

	dialers := make(map[string]Dialer)
	for name, dailer := range config.Dialer {
		u, err := url.Parse(dailer)
		if err != nil {
			log.Fatal().Err(err).Str("dailer", dailer).Msg("parse dailer url failed")
		}
		switch u.Scheme {
		case "local":
			dialers[name] = &LocalDialer{
				Resolver:        geoResolver.Resolver,
				ResolveCache:    dialer.ResolveCache,
				Interface:       u.Host,
				PerferIPv6:      u.Query().Get("prefer_ipv6") == "true",
				Concurrency:     2,
				ForbidLocalAddr: config.Global.ForbidLocalAddr,
				DialTimeout:     time.Duration(cmp.Or(first(strconv.Atoi(u.Query().Get("dial_timeout"))), config.Global.DialTimeout, 30)) * time.Second,
				TCPKeepAlive:    30 * time.Second,
				TLSConfig: &tls.Config{
					InsecureSkipVerify: u.Query().Get("insecure") == "true",
					ClientSessionCache: tls.NewLRUClientSessionCache(2048),
				},
			}
		case "http", "https", "ws", "wss":
			dialers[name] = &HTTPDialer{
				Username:   u.User.Username(),
				Password:   first(u.User.Password()),
				Host:       u.Hostname(),
				Port:       cmp.Or(u.Port(), map[string]string{"http": "80", "https": "443", "ws": "80", "wss": "443"}[u.Scheme]),
				TLS:        u.Scheme == "https" || u.Scheme == "wss",
				Websocket:  u.Scheme == "ws" || u.Scheme == "wss",
				UserAgent:  cmp.Or(u.Query().Get("user_agent"), DefaultUserAgent),
				Insecure:   u.Query().Get("insecure") == "true",
				CACert:     u.Query().Get("cacert"),
				ClientKey:  u.Query().Get("key"),
				ClientCert: u.Query().Get("cert"),
				Resolve:    map[string]string{u.Host: u.Query().Get("resolve")},
				Dialer:     dialer,
			}
		case "http2":
			dialers[name] = &HTTP2Dialer{
				Username:   u.User.Username(),
				Password:   first(u.User.Password()),
				Host:       u.Hostname(),
				Port:       u.Port(),
				UserAgent:  cmp.Or(u.Query().Get("user_agent"), DefaultUserAgent),
				CACert:     u.Query().Get("cacert"),
				ClientKey:  u.Query().Get("key"),
				ClientCert: u.Query().Get("cert"),
				MaxClients: cmp.Or(first(strconv.Atoi(u.Query().Get("max_clients"))), 8),
				Dialer:     dialer,
			}
		case "http3", "http3+wss":
			dialers[name] = &HTTP3Dialer{
				Username:  u.User.Username(),
				Password:  first(u.User.Password()),
				Host:      u.Hostname(),
				Port:      u.Port(),
				UserAgent: cmp.Or(u.Query().Get("user_agent"), DefaultUserAgent),
				Websocket: strings.HasSuffix(u.Scheme, "+wss"),
				Resolver:  geoResolver.Resolver,
			}
		case "socks", "socks5", "socks5h":
			dialers[name] = &Socks5Dialer{
				Username: u.User.Username(),
				Password: first(u.User.Password()),
				Host:     u.Hostname(),
				Port:     u.Port(),
				Socks5H:  u.Scheme == "socks5h",
				Resolver: geoResolver.Resolver,
				Dialer:   dialer,
			}
		case "socks4", "socks4a":
			dialers[name] = &Socks4Dialer{
				Username: u.User.Username(),
				Password: first(u.User.Password()),
				Host:     u.Hostname(),
				Port:     u.Port(),
				Socks4A:  u.Scheme == "socks4a",
				Resolver: geoResolver.Resolver,
				Dialer:   dialer,
			}
		case "ssh", "ssh2":
			dialers[name] = &SSHDialer{
				Username:              u.User.Username(),
				Password:              first(u.User.Password()),
				PrivateKey:            string(first(os.ReadFile(u.Query().Get("key")))),
				Host:                  u.Hostname(),
				Port:                  cmp.Or(u.Port(), "22"),
				StrictHostKeyChecking: cmp.Or(u.Query().Get("StrictHostKeyChecking") == "yes", u.Query().Get("strict_host_key_checking") == "yes"),
				UserKnownHostsFile:    cmp.Or(u.Query().Get("UserKnownHostsFile"), u.Query().Get("user_known_hosts_file")),
				MaxClients:            cmp.Or(first(strconv.Atoi(u.Query().Get("max_clients"))), 8),
				Timeout:               time.Duration(cmp.Or(first(strconv.Atoi(u.Query().Get("timeout"))), 10)) * time.Second,
				Dialer:                dialer,
			}
		default:
			log.Fatal().Str("dialer_scheme", u.Scheme).Msgf("unsupported dialer=%+v", u)
		}
	}

	// see http.DefaultTransport
	transport := &http.Transport{
		DialContext: dialer.DialContext,
		// DialTLSContext:        dialer.DialTLSContext,
		TLSClientConfig:       dialer.TLSConfig,
		MaxIdleConns:          cmp.Or(config.Global.MaxIdleConns, 100),
		IdleConnTimeout:       time.Duration(cmp.Or(config.Global.IdleConnTimeout, 90)) * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
		DisableCompression:    false,
	}

	// useragent caching map
	useragentMap := NewCachingMap(
		func(key string) (useragent.UserAgent, error) {
			return useragent.Parse(key), nil
		},
		4096,
		5*time.Minute,
	)

	// template functions
	functions := &Functions{
		Context:        context.Background(),
		GeoResolver:    geoResolver,
		GeoCache:       lru.NewTTLCache[string, *GeoipInfo](8192),
		GeoSite:        &geosite.DomainListCommunity{Transport: transport},
		GeoSiteCache:   lru.NewTTLCache[string, *string](8192),
		FetchUserAgent: ChromeUserAgent,
		FetchClient:    &http.Client{Transport: transport},
		FetchCache:     lru.NewTTLCache[string, *FetchResponse](8192),
		RegexpCache:    xsync.NewMapOf[string, *regexp.Regexp](),
	}
	if err := functions.Load(); err != nil {
		log.Fatal().Err(err).Msgf("%T.Load() fatal", functions)
	}
	log.Info().Msgf("%T.Load() ok", functions.GeoSite)

	lc := ListenConfig{
		FastOpen:    false,
		ReusePort:   true,
		DeferAccept: true,
	}

	memoryListeners := xsync.NewMapOf[string, *MemoryListener]()
	for _, tunnel := range config.Tunnel {
		memoryListeners.Store(tunnel.Listen[0], nil)
	}

	servers := make([]*http.Server, 0)

	// listen and serve https
	tlsConfigurator := &TLSInspector{
		ClientHelloMap: xsync.NewMapOf[string, *tls.ClientHelloInfo](),
	}
	h2handlers := map[string]map[string]HTTPHandler{}
	for _, server := range config.Https {
		handler := &HTTPServerHandler{
			ForwardHandler: &HTTPForwardHandler{
				Config:         server,
				ForwardLogger:  forwardLogger,
				LocalDialer:    dialer,
				LocalTransport: transport,
				Dialers:        dialers,
				Functions:      functions.FuncMap,
			},
			TunnelHandler: &HTTPTunnelHandler{
				Config: server,
			},
			WebHandler: &HTTPWebHandler{
				Config:    server,
				Transport: transport,
				Functions: functions.FuncMap,
			},
			ServerNames:    server.ServerName,
			ClientHelloMap: tlsConfigurator.ClientHelloMap,
			UserAgentMap:   useragentMap,
			GeoResolver:    geoResolver,
			Config:         server,
		}

		for _, h := range []HTTPHandler{
			handler.ForwardHandler,
			handler.TunnelHandler,
			handler.WebHandler,
			handler,
		} {
			err = h.Load()
			if err != nil {
				log.Fatal().Err(err).Strs("server_name", server.ServerName).Msgf("%T.Load() return error: %+v", h, err)
			}
			log.Info().Strs("server_name", server.ServerName).Msgf("%T.Load() ok", h)
		}

		// add support for ip tls certificate
		if len(server.ServerName) > 0 && net.ParseIP(server.ServerName[0]) != nil {
			server.ServerName = append(server.ServerName, "")
		}

		for _, listen := range server.Listen {
			for _, sniproxy := range server.Sniproxy {
				tlsConfigurator.AddSniproxy(TLSInspectorSniproxy{
					ServerName: sniproxy.ServerName,
					ProxyPass:  sniproxy.ProxyPass,
					Dialer:     dialer,
				})
			}
			for _, name := range server.ServerName {
				config, _ := server.ServerConfig[name]
				if config.Keyfile == "" {
					config.Keyfile, config.Certfile = server.Keyfile, server.Certfile
				}
				if config.Certfile == "" {
					config.Certfile = config.Keyfile
				}
				tlsConfigurator.AddCertEntry(TLSInspectorEntry{
					ServerName:     name,
					KeyFile:        config.Keyfile,
					CertFile:       config.Certfile,
					DisableHTTP2:   config.DisableHttp2,
					DisableTLS11:   config.DisableTls11,
					PreferChacha20: config.PreferChacha20,
					DisableOCSP:    config.DisableOcsp,
				})
				if tlsConfigurator.DefaultServername == "" {
					tlsConfigurator.DefaultServername = name
				}
				hs, ok := h2handlers[listen]
				if !ok {
					hs = make(map[string]HTTPHandler)
					h2handlers[listen] = hs
				}
				hs[name] = handler
			}
		}
	}

	for addr, handlers := range h2handlers {
		addr, handlers := addr, handlers

		var ln net.Listener

		if ln, err = lc.Listen(context.Background(), "tcp", addr); err != nil {
			log.Fatal().Err(err).Str("address", addr).Msg("net.Listen error")
		}

		log.Info().Str("version", version).Str("address", ln.Addr().String()).Msg("liner listen and serve tls")

		server := &http.Server{
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if s, _, err := net.SplitHostPort(r.TLS.ServerName); err == nil {
					r.TLS.ServerName = s
				}
				var serverName = r.TLS.ServerName
				if serverName == "" {
					serverName = tlsConfigurator.DefaultServername
				}

				h, _ := handlers[serverName]
				if h == nil {
					for key, value := range handlers {
						if key != "" && key[0] == '*' && strings.HasSuffix(serverName, key[1:]) {
							h = value
							break
						}
					}
				}
				if h == nil {
					http.NotFound(w, r)
					return
				}
				h.ServeHTTP(w, r)
			}),
			TLSConfig: &tls.Config{
				GetConfigForClient: tlsConfigurator.GetConfigForClient,
			},
			ConnState: tlsConfigurator.ConnState,
			ErrorLog:  log.DefaultLogger.Std("", 0),
		}

		http2.ConfigureServer(server, &http2.Server{
			MaxConcurrentStreams:         100,
			MaxUploadBufferPerStream:     1024 * 1024,
			MaxUploadBufferPerConnection: 100 * 1024 * 1024, // 100 MB, https: //github.com/golang/go/issues/54330#issuecomment-1213576274
			MaxReadFrameSize:             1024 * 1024,       // 1MB read frame, https://github.com/golang/go/issues/47840
		})

		go server.Serve(TCPListener{
			TCPListener:     ln.(*net.TCPListener),
			KeepAlivePeriod: 3 * time.Minute,
			// ReadBufferSize:  1 << 20,
			// WriteBufferSize: 1 << 20,
			MirrorHeader: true,
			TLSConfig:    server.TLSConfig,
		})

		servers = append(servers, server)

		// start http3 server
		if !config.Global.DisableHttp3 {
			go (&http3.Server{
				Addr:      addr,
				Handler:   server.Handler,
				TLSConfig: server.TLSConfig,
				Logger:    log.DefaultLogger.Slog().With("logger", "http3_server"),
				QUICConfig: &quic.Config{
					Allow0RTT:                  true,
					DisablePathMTUDiscovery:    false,
					EnableDatagrams:            true,
					MaxIncomingStreams:         100,
					MaxStreamReceiveWindow:     6 * 1024 * 1024,
					MaxConnectionReceiveWindow: 100 * 6 * 1024 * 1024,
				},
			}).ListenAndServe()
		}
	}

	// listen and serve http
	h1handlers := map[string]HTTPHandler{}
	for _, httpConfig := range config.Http {
		httpConfig.ServerName = append(httpConfig.ServerName, "", "localhost", "127.0.0.1")
		if name, err := os.Hostname(); err == nil {
			httpConfig.ServerName = append(httpConfig.ServerName, name)
		}
		if ip, err := GetPreferedLocalIP(); err == nil {
			httpConfig.ServerName = append(httpConfig.ServerName, ip.String())
		}
		handler := &HTTPServerHandler{
			ForwardHandler: &HTTPForwardHandler{
				Config:         httpConfig,
				ForwardLogger:  forwardLogger,
				LocalDialer:    dialer,
				LocalTransport: transport,
				Dialers:        dialers,
				Functions:      functions.FuncMap,
			},
			TunnelHandler: &HTTPTunnelHandler{
				Config: httpConfig,
			},
			WebHandler: &HTTPWebHandler{
				Config:    httpConfig,
				Transport: transport,
				Functions: functions.FuncMap,
			},
			ServerNames:    httpConfig.ServerName,
			ClientHelloMap: tlsConfigurator.ClientHelloMap,
			UserAgentMap:   useragentMap,
			GeoResolver:    geoResolver,
			Config:         httpConfig,
		}

		for _, h := range []HTTPHandler{
			handler.ForwardHandler,
			handler.TunnelHandler,
			handler.WebHandler,
			handler,
		} {
			err = h.Load()
			if err != nil {
				log.Fatal().Err(err).Strs("server_name", httpConfig.ServerName).Msgf("%T.Load() return error: %+v", h, err)
			}
			log.Info().Strs("server_name", httpConfig.ServerName).Msgf("%T.Load() ok", h)
		}

		for _, listen := range httpConfig.Listen {
			h1handlers[listen] = handler
		}
	}

	for addr, handler := range h1handlers {
		addr, handler := addr, handler

		var ln net.Listener

		if ln, err = lc.Listen(context.Background(), "tcp", addr); err != nil {
			log.Fatal().Err(err).Str("address", addr).Msg("net.Listen error")
		}

		log.Info().Str("version", version).Str("address", ln.Addr().String()).Msg("liner listen and serve")

		server := &http.Server{
			Handler:  handler,
			ErrorLog: log.DefaultLogger.Std("", 0),
		}

		ln = TCPListener{
			TCPListener:     ln.(*net.TCPListener),
			KeepAlivePeriod: 3 * time.Minute,
			ReadBufferSize:  32 * 1024,
			WriteBufferSize: 32 * 1024,
		}
		if _, ok := memoryListeners.Load(addr); ok {
			newln := &MemoryListener{Listener: ln}
			memoryListeners.Store(addr, newln)
			ln = newln
		}

		go server.Serve(ln)

		servers = append(servers, server)
	}

	// socks handler
	for _, socksConfig := range config.Socks {
		for _, addr := range socksConfig.Listen {
			var ln net.Listener

			if ln, err = lc.Listen(context.Background(), "tcp", addr); err != nil {
				log.Fatal().Err(err).Str("address", addr).Msg("net.Listen error")
			}

			log.Info().Str("version", version).Str("address", ln.Addr().String()).Msg("liner listen and serve socks")

			h := &SocksHandler{
				Config:        socksConfig,
				ForwardLogger: forwardLogger,
				GeoResolver:   geoResolver,
				LocalDialer:   dialer,
				Dialers:       dialers,
				Functions:     functions.FuncMap,
			}

			if err = h.Load(); err != nil {
				log.Fatal().Err(err).Str("address", addr).Msg("socks hanlder load error")
			}

			go func(ln net.Listener, h *SocksHandler) {
				for {
					conn, err := ln.Accept()
					if err != nil {
						log.Error().Err(err).Str("version", version).Str("address", ln.Addr().String()).Msg("liner accept socks connection error")
						time.Sleep(10 * time.Millisecond)
						continue
					}
					go h.ServeConn(context.Background(), conn)
				}
			}(ln, h)
		}
	}

	// stream handler
	for _, streamConfig := range config.Stream {
		for _, addr := range streamConfig.Listen {
			var ln net.Listener

			if ln, err = lc.Listen(context.Background(), "tcp", addr); err != nil {
				log.Fatal().Err(err).Str("address", addr).Msg("net.Listen error")
			}

			log.Info().Str("version", version).Str("address", ln.Addr().String()).Msg("liner listen and forward port")

			h := &StreamHandler{
				Config:        streamConfig,
				ForwardLogger: forwardLogger,
				GeoResolver:   geoResolver,
				LocalDialer:   dialer,
				Dialers:       dialers,
			}

			if err = h.Load(); err != nil {
				log.Fatal().Err(err).Str("address", addr).Msg("stream hanlder load error")
			}

			go func(ln net.Listener, h *StreamHandler) {
				for {
					conn, err := ln.Accept()
					if err != nil {
						log.Error().Err(err).Str("version", version).Str("address", ln.Addr().String()).Msg("liner accept stream connection error")
						time.Sleep(10 * time.Millisecond)
						continue
					}
					go h.ServeConn(conn)
				}
			}(ln, h)
		}
	}

	// tunnel handler
	for _, tunnel := range config.Tunnel {
		h := &TunnelHandler{
			Config:          tunnel,
			MemoryListeners: memoryListeners,
			Resolver:        geoResolver.Resolver,
			LocalDialer:     dialer,
			Dialers:         config.Dialer,
		}
		if tunnel.DnsServer != "" {
			h.Resolver = resolverof(tunnel.DnsServer)
		}

		go h.Serve(context.Background())
	}

	var cronOptions = []cron.Option{
		cron.WithSeconds(),
		cron.WithLogger(cron.PrintfLogger(&log.DefaultLogger)),
	}
	if !config.Global.LogLocaltime {
		cronOptions = append(cronOptions, cron.WithLocation(time.UTC))
	}
	runner := cron.New(cronOptions...)
	if !log.IsTerminal(os.Stderr.Fd()) {
		runner.AddFunc("0 0 0 * * *", func() { log.DefaultLogger.Writer.(*log.FileWriter).Rotate() })
		runner.AddFunc("0 0 0 * * *", func() { forwardLogger.Writer.(*log.AsyncWriter).Writer.(*log.FileWriter).Rotate() })
	}
	for _, job := range config.Cron {
		spec, command := job.Spec, job.Command
		runner.AddFunc(spec, func() {
			cmd := exec.CommandContext(context.Background(), "/bin/bash", "-c", command)
			err = cmd.Run()
			if err != nil {
				log.Warn().Strs("cmd_args", cmd.Args).Err(err).Msg("exec cron_command error")
				return
			}
			log.Info().Str("cron_command", command).Msg("exec cron_command OK")
		})
		log.Info().Str("cron_spec", spec).Str("cron_command", command).Msg("add cron job OK")
	}
	go runner.Run()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGTERM)
	signal.Notify(c, syscall.SIGINT)
	signal.Notify(c, syscall.SIGHUP)

	<-c

	log.Info().Msg("liner flush logs and exit.")
	log.DefaultLogger.Writer.(io.Closer).Close()
	forwardLogger.Writer.(io.Closer).Close()
	log.Info().Msg("liner server shutdown")
}
