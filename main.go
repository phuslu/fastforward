package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oschwald/maxminddb-golang"
	"github.com/phuslu/log"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/robfig/cron/v3"
	"golang.org/x/net/http2"
	"golang.org/x/sync/singleflight"
)

var (
	version = "1984"
	timeNow = time.Now

	DefaultUserAgent = "Liner/" + version
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
			dnsDialer := &net.Dialer{
				Timeout: 2 * time.Second,
			}
			resolver.Resolver.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
				return dnsDialer.DialContext(ctx, u.Scheme, addr)
			}
		case "tls", "dot":
			var addr = u.Host
			if _, _, err := net.SplitHostPort(u.Host); err != nil {
				addr = net.JoinHostPort(addr, "853")
			}
			tlsDialer := &tls.Dialer{
				NetDialer: &net.Dialer{
					Timeout: 2 * time.Second,
				},
				Config: &tls.Config{
					ServerName:         u.Hostname(),
					ClientSessionCache: tls.NewLRUClientSessionCache(128),
				},
			}
			resolver.Resolver.Dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
				return tlsDialer.DialContext(ctx, "tcp", addr)
			}
		case "https", "http2", "h2", "doh":
			resolver.Resolver.Dial = (&DoHResolverDialer{
				EndPoint:  strings.NewReplacer("http2", "https", "h2", "https", "doh", "https").Replace(config.Global.DnsServer),
				UserAgent: u.Query().Get("user_agent"),
				Transport: &http2.Transport{
					TLSClientConfig: &tls.Config{
						ServerName:         u.Hostname(),
						ClientSessionCache: tls.NewLRUClientSessionCache(128),
					},
				},
			}).DialContext
		case "http3", "h3":
			resolver.Resolver.Dial = (&DoHResolverDialer{
				EndPoint:  strings.NewReplacer("http3", "https", "h3", "https").Replace(config.Global.DnsServer),
				UserAgent: u.Query().Get("user_agent"),
				Transport: &http3.RoundTripper{
					DisableCompression: false,
					EnableDatagrams:    false,
					TLSClientConfig: &tls.Config{
						NextProtos:         []string{"h3"},
						InsecureSkipVerify: u.Query().Get("insecure") == "1",
						ServerName:         u.Hostname(),
						ClientSessionCache: tls.NewLRUClientSessionCache(128),
					},
					QuicConfig: &quic.Config{
						DisablePathMTUDiscovery: false,
						EnableDatagrams:         false,
						MaxIncomingUniStreams:   200,
						MaxIncomingStreams:      200,
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
		Resolver:        resolver,
		Concurrency:     2,
		ForbidLocalAddr: config.Global.ForbidLocalAddr,
		ReadBuffSize:    config.Global.DialReadBuffer,
		WriteBuffSize:   config.Global.DialWriteBuffer,
		DialTimeout:     30 * time.Second,
		TCPKeepAlive:    30 * time.Second,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			ClientSessionCache: tls.NewLRUClientSessionCache(2048),
		},
	}

	if config.Global.DialTimeout > 0 {
		dialer.DialTimeout = time.Duration(config.Global.DialTimeout) * time.Second
	}

	upstreams := make(map[string]Dialer)
	for name, upstream := range config.Upstream {
		u, err := url.Parse(upstream)
		if err != nil {
			log.Fatal().Err(err).Str("upstream", upstream).Msg("parse upstream url failed")
		}
		switch u.Scheme {
		case "http":
			upstreams[name] = &HTTPDialer{
				Username:  u.User.Username(),
				Password:  first(u.User.Password()),
				Host:      u.Hostname(),
				Port:      u.Port(),
				UserAgent: u.Query().Get("user_agent"),
				Dialer:    dialer,
			}
		case "https":
			upstreams[name] = &HTTPDialer{
				Username:  u.User.Username(),
				Password:  first(u.User.Password()),
				Host:      u.Hostname(),
				Port:      u.Port(),
				UserAgent: u.Query().Get("user_agent"),
				Dialer:    dialer,
				TLSConfig: &tls.Config{
					InsecureSkipVerify: false,
					ServerName:         u.Hostname(),
					ClientSessionCache: tls.NewLRUClientSessionCache(1024),
				},
			}
		case "http2":
			upstreams[name] = &HTTP2Dialer{
				Username:   u.User.Username(),
				Password:   first(u.User.Password()),
				Host:       u.Hostname(),
				Port:       u.Port(),
				UserAgent:  u.Query().Get("user_agent"),
				MaxClients: first(strconv.Atoi(u.Query().Get("max_clients"))),
				Dialer:     dialer,
			}
		case "http3":
			upstreams[name] = &HTTP3Dialer{
				Username:  u.User.Username(),
				Password:  first(u.User.Password()),
				Host:      u.Hostname(),
				Port:      u.Port(),
				UserAgent: u.Query().Get("user_agent"),
				Resolver:  resolver,
			}
		case "websocket", "wss":
			upstreams[name] = &WebsocketDialer{
				EndpointFormat: fmt.Sprintf("https://%s%s", u.Host, u.RequestURI()),
				Username:       u.User.Username(),
				Password:       first(u.User.Password()),
				UserAgent:      u.Query().Get("user_agent"),
				Dialer:         dialer,
				TLSConfig: &tls.Config{
					InsecureSkipVerify: false,
					ServerName:         u.Hostname(),
					ClientSessionCache: tls.NewLRUClientSessionCache(1024),
				},
			}
		case "socks", "socks5", "socks5h":
			upstreams[name] = &Socks5Dialer{
				Username: u.User.Username(),
				Password: first(u.User.Password()),
				Host:     u.Hostname(),
				Port:     u.Port(),
				Socsk5H:  u.Scheme == "socks5h",
				Resolver: resolver,
				Dialer:   dialer,
			}
		case "socks4", "socks4a":
			upstreams[name] = &Socks4Dialer{
				Username: u.User.Username(),
				Password: first(u.User.Password()),
				Host:     u.Hostname(),
				Port:     u.Port(),
				Socks4A:  u.Scheme == "socks4a",
				Resolver: resolver,
				Dialer:   dialer,
			}
		case "ssh", "ssh2":
			upstreams[name] = &SSHDialer{
				Username:   u.User.Username(),
				Password:   first(u.User.Password()),
				PrivateKey: string(first(os.ReadFile(u.Query().Get("keyfile")))),
				Host:       u.Hostname(),
				Port:       u.Port(),
				MaxClients: first(strconv.Atoi(u.Query().Get("max_clients"))),
				Timeout:    time.Duration(first(strconv.Atoi(u.Query().Get("timeout")))) * time.Second,
				Dialer:     dialer,
			}
		default:
			log.Fatal().Str("upstream_scheme", u.Scheme).Msgf("unsupported upstream=%+v", u)
		}
	}

	// see http.DefaultTransport
	transport := &http.Transport{
		DialContext: dialer.DialContext,
		// DialTLSContext:        dialer.DialTLSContext,
		TLSClientConfig:       dialer.TLSConfig,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
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
		FastOpen:    false,
		ReusePort:   true,
		DeferAccept: true,
	}

	servers := make([]*http.Server, 0)

	// listen and serve https
	tlsConfigurator := &TLSConfigurator{}
	h2handlers := map[string]map[string]HTTPHandler{}
	for _, server := range config.Https {
		handler := &HTTPServerHandler{
			ForwardHandler: &HTTPForwardHandler{
				Config:         server,
				ForwardLogger:  forwardLogger,
				RegionResolver: regionResolver,
				LocalDialer:    dialer,
				Transport:      transport,
				Upstreams:      upstreams,
				Functions:      functions,
			},
			WebHandler: &HTTPWebHandler{
				Config:    server,
				Transport: transport,
				Functions: functions,
			},
			ServerNames:     NewStringSet(server.ServerName),
			TLSConfigurator: tlsConfigurator,
			Config:          server,
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
				keyfile, certfile := server.Keyfile, server.Certfile
				if server.Keyfiles[name] != "" {
					keyfile = server.Keyfiles[name]
				}
				if server.Certfiles[name] != "" {
					certfile = server.Certfiles[name]
				}
				tlsConfigurator.AddCertEntry(TLSConfiguratorEntry{
					ServerName:     name,
					KeyFile:        keyfile,
					CertFile:       certfile,
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
			MaxReadFrameSize:             1 << 20, // 256K read frame, https://github.com/golang/go/issues/47840
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
		if !config.Global.DisableHTTP3 {
			go (&http3.Server{
				Addr:      addr,
				Handler:   server.Handler,
				TLSConfig: server.TLSConfig,
				QuicConfig: &quic.Config{
					Allow0RTT:               true,
					DisablePathMTUDiscovery: false,
					EnableDatagrams:         false,
					// MaxStreamReceiveWindow:     6 * 1024 * 1024,
					// MaxConnectionReceiveWindow: 15 * 1024 * 1024,
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
				RegionResolver: regionResolver,
				LocalDialer:    dialer,
				Transport:      transport,
				Upstreams:      upstreams,
				Functions:      functions,
			},
			WebHandler: &HTTPWebHandler{
				Config:    httpConfig,
				Transport: transport,
				Functions: functions,
			},
			ServerNames:     NewStringSet(httpConfig.ServerName),
			TLSConfigurator: tlsConfigurator,
			Config:          httpConfig,
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

	// stream handler
	for _, streamConfig := range config.Stream {
		for _, addr := range streamConfig.Listen {
			var ln net.Listener

			if ln, err = lc.Listen(context.Background(), "tcp", addr); err != nil {
				log.Fatal().Err(err).Str("address", addr).Msg("net.Listen error")
			}

			log.Info().Str("version", version).Str("address", ln.Addr().String()).Msg("liner listen and forward port")

			h := &StreamHandler{
				Config:         streamConfig,
				ForwardLogger:  forwardLogger,
				RegionResolver: regionResolver,
				LocalDialer:    dialer,
				Upstreams:      upstreams,
			}

			if err = h.Load(); err != nil {
				log.Fatal().Err(err).Str("address", addr).Msg("socks hanlder load error")
			}

			go func(ln net.Listener, h *StreamHandler) {
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
		runner.AddFunc("0 0 * * * *", func() { log.DefaultLogger.Writer.(*log.FileWriter).Rotate() })
		runner.AddFunc("0 0 * * * *", func() { forwardLogger.Writer.(*log.FileWriter).Rotate() })
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

	var wg sync.WaitGroup
	for _, server := range servers {
		wg.Add(1)
		go func(server *http.Server) {
			defer wg.Done()

			timeout := 5 * time.Minute
			if config.Global.GracefulTimeout > 0 {
				timeout = time.Duration(config.Global.GracefulTimeout) * time.Second
			}

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
