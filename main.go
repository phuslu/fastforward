package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/oschwald/maxminddb-golang"
	"github.com/phuslu/log"
	"github.com/robfig/cron/v3"
	"golang.org/x/net/http2"
	"golang.org/x/sync/singleflight"
)

var (
	version = "r1984"
	timeNow = time.Now
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

	if IsSupervisorProcess() {
		go StartWorkerProcess(0, os.Args[0], os.Args[1:], ".", nil)
		StartWorkerSupervisor()
		return
	}

	flag.Parse()
	config, err := NewConfig(flag.Arg(0))
	if err != nil {
		log.Fatal().Err(err).Str("filename", flag.Arg(0)).Msg("NewConfig() error")
		os.Exit(1)
	}

	// main logger
	var forwardLogger log.Logger
	if log.IsTerminal(os.Stderr.Fd()) {
		log.DefaultLogger = log.Logger{
			Level:      log.ParseLevel(config.Global.LogLevel),
			Caller:     1,
			TimeFormat: "15:04:05",
			Writer: &log.ConsoleWriter{
				ColorOutput:    true,
				EndWithMessage: true,
			},
		}
		forwardLogger = log.Logger{
			Level:  log.ParseLevel(config.Global.LogLevel),
			Writer: log.DefaultLogger.Writer,
		}
	} else {
		// main logger
		log.DefaultLogger = log.Logger{
			Level: log.ParseLevel(config.Global.LogLevel),
			Writer: &log.FileWriter{
				Filename:   executable + ".log",
				MaxBackups: 1,
				MaxSize:    config.Global.LogMaxsize,
				LocalTime:  config.Global.LogLocaltime,
			},
		}
		// forward logger
		forwardLogger = log.Logger{
			Level: log.ParseLevel(config.Global.LogLevel),
			Writer: &log.FileWriter{
				Filename:   "forward.log",
				MaxBackups: config.Global.LogBackups,
				MaxSize:    config.Global.LogMaxsize,
				LocalTime:  config.Global.LogLocaltime,
			},
		}
	}

	// global database
	var db *sql.DB
	if config.Global.DatabaseSource != "" && !strings.HasPrefix(config.Global.DatabaseSource, "csvq://") {
		parts := strings.SplitN(config.Global.DatabaseSource, "://", 2)
		db, err = sql.Open(parts[0], parts[1])
		if err != nil {
			log.Fatal().Err(err).Str("database_source", config.Global.DatabaseSource).Msg("invalid database_source")
		}
	}

	// global resolver
	resolver := &Resolver{
		Resolver: &net.Resolver{
			PreferGo: false,
		},
		LRUCache:      NewLRUCache(32 * 1024),
		CacheDuration: time.Minute,
	}

	if config.Global.DnsCacheDuration != "" {
		dur, err := time.ParseDuration(config.Global.DnsCacheDuration)
		if dur == 0 || err != nil {
			log.Fatal().Err(err).Str("dns_cache_duration", config.Global.DnsCacheDuration).Msg("invalid dns_cache_duration")
		}
		resolver.CacheDuration = dur
	}

	if dnsServer := config.Global.DnsServer; dnsServer != "" {
		if !strings.Contains(dnsServer, "://") {
			dnsServer = "udp://" + dnsServer
		}
		u, err := url.Parse(dnsServer)
		if err != nil {
			log.Fatal().Err(err).Str("dns_server", config.Global.DnsServer).Msg("parse dns_server error")
		}
		if u.Scheme == "" || u.Host == "" {
			log.Fatal().Err(errors.New("no scheme or host")).Str("dns_server", config.Global.DnsServer).Msg("parse dns_server error")
		}

		switch u.Scheme {
		case "udp", "tcp":
			var addr = u.Host
			if _, _, err := net.SplitHostPort(u.Host); err != nil {
				addr = net.JoinHostPort(addr, "53")
			}
			resolver.Resolver.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, u.Scheme, addr)
			}
		case "tls", "dot":
			var addr = u.Host
			if _, _, err := net.SplitHostPort(u.Host); err != nil {
				addr = net.JoinHostPort(addr, "853")
			}
			tlsConfig := &tls.Config{
				ServerName:         u.Hostname(),
				ClientSessionCache: tls.NewLRUClientSessionCache(128),
			}
			resolver.Resolver.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
				return tls.Dial("tcp", addr, tlsConfig)
			}
		case "https", "doh":
			resolver.Resolver.Dial = (&DoHDialer{
				EndPoint:  config.Global.DnsServer,
				UserAgent: DefaultUserAgent,
				Transport: &http2.Transport{
					TLSClientConfig: &tls.Config{
						ServerName:         u.Hostname(),
						ClientSessionCache: tls.NewLRUClientSessionCache(128),
					},
				},
			}).DialContext
		}
	}

	regionResolver := &RegionResolver{
		Resolver: resolver,
	}

	if names, _ := filepath.Glob("*.mmdb"); len(names) != 0 {
		regionResolver.MaxmindReader, err = maxminddb.Open(names[0])
		if err != nil {
			log.Fatal().Err(err).Str("geoip2_database", names[0]).Msg("load geoip2_database error")
		}
	}

	// global dialer
	dialer := &LocalDialer{
		Resolver:              resolver,
		ParallelLevel:         2,
		DenyIntranet:          config.Global.DenyIntranet,
		Timeout:               30 * time.Second,
		TCPKeepAlive:          30 * time.Second,
		TLSClientSessionCache: tls.NewLRUClientSessionCache(2048),
	}

	if config.Global.DialTimeout > 0 {
		dialer.Timeout = time.Duration(config.Global.DialTimeout) * time.Second
	}

	if config.Global.PreferIpv6 {
		dialer.PreferIPv6 = true
		dialer.ParallelLevel = 1
	}

	upstreams := make(map[string]Dialer)
	for name, upstream := range config.Upstream {
		parts := strings.SplitN(upstream, "\n", 2)
		u, err := url.Parse(parts[0])
		if err != nil {
			log.Fatal().Err(err).Str("upstream", parts[0]).Msg("parse upstream url failed")
		}
		extra := ""
		if len(parts) > 1 {
			extra = strings.TrimSpace(parts[1])
		}
		username := u.User.Username()
		password, _ := u.User.Password()
		switch u.Scheme {
		case "http", "http1":
			upstreams[name] = &HTTPDialer{
				Username:  username,
				Password:  password,
				Host:      u.Hostname(),
				Port:      u.Port(),
				UserAgent: extra,
				Resolver:  resolver,
				Dialer:    dialer,
			}
		case "https", "http2":
			upstreams[name] = &HTTP2Dialer{
				Username:  username,
				Password:  password,
				Host:      u.Hostname(),
				Port:      u.Port(),
				UserAgent: extra,
			}
		case "socks", "socks5", "socks5h":
			upstreams[name] = &Socks5Dialer{
				Username: username,
				Password: password,
				Host:     u.Hostname(),
				Port:     u.Port(),
				Socsk5H:  u.Scheme == "socks5h",
				Resolver: resolver,
				Dialer:   dialer,
			}
		case "socks4", "socks4a":
			upstreams[name] = &Socks4Dialer{
				Username: username,
				Password: password,
				Host:     u.Hostname(),
				Port:     u.Port(),
				Socks4A:  u.Scheme == "socks4a",
				Resolver: resolver,
				Dialer:   dialer,
			}
		case "ssh", "ssh2":
			upstreams[name] = &SSHDialer{
				Username:   username,
				Password:   password,
				PrivateKey: extra,
				Host:       u.Hostname(),
				Port:       u.Port(),
				Dialer:     dialer,
				Timeout:    10 * time.Second,
				MaxClients: 4,
			}
		default:
			log.Fatal().Str("upstream_scheme", u.Scheme).Msgf("unsupported upstream=%+v", u)
		}
	}

	// see http.DefaultTransport
	transport := &http.Transport{
		DialContext: dialer.DialContext,
		DialTLS: func(network, address string) (net.Conn, error) {
			return dialer.DialTLS(network, address, &tls.Config{
				InsecureSkipVerify: true,
				ClientSessionCache: dialer.TLSClientSessionCache,
			})
		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    false,
	}

	if config.Global.MaxIdleConns > 0 {
		transport.MaxIdleConns = config.Global.MaxIdleConns
	}

	if config.Global.IdleConnTimeout > 0 {
		transport.IdleConnTimeout = time.Duration(config.Global.IdleConnTimeout) * time.Second
	}

	functions := (&Functions{
		RegionResolver: regionResolver,
		LRUCache:       NewLRUCache(128),
		Singleflight:   &singleflight.Group{},
	}).FuncMap()

	lc := ListenConfig{
		FastOpen:    config.Global.TcpFastopen,
		ReusePort:   true,
		DeferAccept: true,
	}

	servers := make([]*http.Server, 0)

	// listen and serve https
	tlsConfigurator := &TLSConfigurator{}
	h2handlers := map[string]map[string]HTTPHandler{}
	for _, server := range config.Https {
		handler := &HTTPMainHandler{
			ForwardHandler: &HTTPForwardHandler{
				Config:         server,
				ForwardLogger:  forwardLogger,
				RegionResolver: regionResolver,
				LocalDialer:    dialer,
				Transport:      transport,
				Upstreams:      upstreams,
				Functions:      functions,
				DB:             db,
			},
			WebHandler: &HTTPWebHandler{
				Config:    server,
				Transport: transport,
				Functions: functions,
			},
			ServerNames:     NewStringSet(server.ServerName),
			TLSConfigurator: tlsConfigurator,
		}

		for _, h := range []HTTPHandler{handler.ForwardHandler, handler.WebHandler, handler} {
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
			for _, name := range server.ServerName {
				tlsConfigurator.AddCertEntry(TLSConfiguratorEntry{
					ServerName:     name,
					KeyFile:        server.Keyfile,
					CertFile:       server.Certfile,
					DisableHTTP2:   server.DisableHttp2,
					DisableTLS11:   server.DisableTls11,
					PreferChacha20: server.PreferChacha20,
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
			MaxUploadBufferPerConnection: 1 << 20,
			MaxUploadBufferPerStream:     1 << 20,
		})

		go server.Serve(tls.NewListener(TCPListener{
			TCPListener:     ln.(*net.TCPListener),
			KeepAlivePeriod: 3 * time.Minute,
			ReadBufferSize:  1 << 20,
			WriteBufferSize: 1 << 20,
		}, server.TLSConfig))

		servers = append(servers, server)

		// start http3 server
		go (&http3.Server{
			Addr:      addr,
			Handler:   server.Handler,
			TLSConfig: server.TLSConfig,
			QuicConfig: &quic.Config{
				EnableDatagrams: true,
			},
		}).ListenAndServe()

		servers = append(servers, server)
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
		handler := &HTTPMainHandler{
			ForwardHandler: &HTTPForwardHandler{
				Config:         httpConfig,
				ForwardLogger:  forwardLogger,
				RegionResolver: regionResolver,
				LocalDialer:    dialer,
				Transport:      transport,
				Upstreams:      upstreams,
				Functions:      functions,
				DB:             db,
			},
			WebHandler: &HTTPWebHandler{
				Config:    httpConfig,
				Transport: transport,
				Functions: functions,
			},
			ServerNames:     NewStringSet(httpConfig.ServerName),
			TLSConfigurator: tlsConfigurator,
		}

		for _, h := range []HTTPHandler{handler.ForwardHandler, handler.WebHandler, handler} {
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

		go server.Serve(TCPListener{
			TCPListener:     ln.(*net.TCPListener),
			KeepAlivePeriod: 3 * time.Minute,
			ReadBufferSize:  32 * 1024,
			WriteBufferSize: 32 * 1024,
		})

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
				Config:         socksConfig,
				ForwardLogger:  forwardLogger,
				RegionResolver: regionResolver,
				LocalDialer:    dialer,
				Upstreams:      upstreams,
				Functions:      functions,
				DB:             db,
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
					}
					go h.ServeConn(conn)
				}
			}(ln, h)
		}
	}

	// relay handler
	for _, relayConfig := range config.Relay {
		for _, addr := range relayConfig.Listen {
			var ln net.Listener

			if ln, err = lc.Listen(context.Background(), "tcp", addr); err != nil {
				log.Fatal().Err(err).Str("address", addr).Msg("net.Listen error")
			}

			log.Info().Str("version", version).Str("address", ln.Addr().String()).Msg("liner listen and forward port")

			h := &RelayHandler{
				Config:         relayConfig,
				ForwardLogger:  forwardLogger,
				RegionResolver: regionResolver,
				LocalDialer:    dialer,
				Upstreams:      upstreams,
			}

			if err = h.Load(); err != nil {
				log.Fatal().Err(err).Str("address", addr).Msg("socks hanlder load error")
			}

			go func(ln net.Listener, h *RelayHandler) {
				for {
					conn, err := ln.Accept()
					if err != nil {
						log.Error().Err(err).Str("version", version).Str("address", ln.Addr().String()).Msg("liner accept socks connection error")
						time.Sleep(10 * time.Millisecond)
					}
					go h.ServeConn(conn)
				}
			}(ln, h)
		}
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
		runner.AddFunc("0 0 0 * * *", func() { forwardLogger.Writer.(*log.FileWriter).Rotate() })
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

	switch <-c {
	case syscall.SIGTERM, syscall.SIGINT:
		log.Info().Msg("liner flush logs and exit.")
		log.DefaultLogger.Writer.(io.Closer).Close()
		os.Exit(0)
	}

	log.Warn().Msg("liner start graceful shutdown...")
	SetProcessName("liner: (graceful shutdown)")

	timeout := 5 * time.Minute
	if config.Global.GracefulTimeout > 0 {
		timeout = time.Duration(config.Global.GracefulTimeout) * time.Second
	}

	var wg sync.WaitGroup
	for _, server := range servers {
		wg.Add(1)
		go func(server *http.Server) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			if err := server.Shutdown(ctx); err != nil {
				log.Error().Err(err).Msgf("%T.Shutdown() error", server)
			}
		}(server)
	}
	wg.Wait()

	log.Info().Msg("liner server shutdown")
}
