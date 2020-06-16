package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"text/template"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/phuslu/log"
	"github.com/tidwall/shardmap"
	"github.com/valyala/fastjson"
	"golang.org/x/net/publicsuffix"
)

type QuicRequest struct {
	RemoteAddr string
	RemoteIP   string
	ServerAddr string
	Username   string
	Password   string
	Network    string
	Host       string
	Port       int
}

type QuicHandler struct {
	Config         QuicConfig
	ForwardLogger  log.Logger
	RegionResolver *RegionResolver
	LocalDialer    *LocalDialer
	Upstreams      map[string]*http.Transport
	Functions      template.FuncMap

	AllowDomains     StringSet
	DenyDomains      StringSet
	PolicyTemplate   *template.Template
	AuthTemplate     *template.Template
	UpstreamTemplate *template.Template
	AuthCache        *shardmap.Map
}

func (h *QuicHandler) Load() error {
	var err error

	expandDomains := func(domains []string) []string {
		var a []string
		for _, s := range domains {
			switch {
			case strings.HasPrefix(s, "@"):
				data, err := ioutil.ReadFile(s[1:])
				if err != nil {
					log.Error().Err(err).Str("forward_domain_file", s[1:]).Msg("read forward domain error")
					continue
				}
				lines := strings.Split(strings.Replace(string(data), "\r\n", "\n", -1), "\n")
				a = append(a, lines...)
			default:
				a = append(a, s)
			}
		}
		return domains
	}

	h.AllowDomains = NewStringSet(expandDomains(h.Config.ForwardAllowDomains))
	h.DenyDomains = NewStringSet(expandDomains(h.Config.ForwardDenyDomains))

	if s := h.Config.ForwardPolicy; s != "" {
		if h.PolicyTemplate, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	if s := h.Config.ForwardAuth; s != "" {
		if h.AuthTemplate, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	if s := h.Config.ForwardUpstream; s != "" {
		if h.UpstreamTemplate, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	if h.Config.ForwardOutboundIp != "" {
		if runtime.GOOS != "linux" {
			log.Fatal().Strs("server_listen", h.Config.Listen).Msg("option outbound_ip is only available on linux")
		}
		if h.Config.ForwardUpstream != "" {
			log.Fatal().Strs("server_listen", h.Config.Listen).Msg("option outbound_ip is confilict with option upstream")
		}

		var dialer = *h.LocalDialer
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(h.Config.ForwardOutboundIp)}
		dialer.Control = (DailerController{BindAddressNoPort: true}).Control
	}

	h.AuthCache = shardmap.New(0)

	return nil
}

func (h *QuicHandler) ServeSession(session quic.Session) {
	var req QuicRequest
	req.RemoteAddr = session.RemoteAddr().String()
	req.RemoteIP, _, _ = net.SplitHostPort(req.RemoteAddr)
	req.ServerAddr = session.LocalAddr().String()

	sendStream, err := session.OpenStream()
	if err != nil {
		log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Msg("quic read handshake error")
		return
	}

	conn := &quicConn{
		session:    session,
		sendStream: sendStream,
	}

	defer conn.Close()

	var b = make([]byte, 1200)

	n, err := conn.Read(b)
	if err != nil || n == 0 {
		log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Msg("quic read handshake error")
		return
	}

	b = b[:n]
	var i = bytes.Index(b, []byte{'\n', '\n'})
	if i <= 0 {
		log.Error().Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Msg("quic read lflf error")
		return
	}

	lines := bytes.Split(b[:i], []byte{'\n'})
	if len(lines) < 3 {
		log.Error().Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Msg("quic split lf error")
		return
	}

	network := string(lines[0])
	host, port, err := net.SplitHostPort(string(lines[1]))
	parts := strings.SplitN(string(lines[2]), ":", 2)
	if err != nil || len(parts) != 2 {
		log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Msg("quic split host port error")
		return
	}

	req.Network = network
	req.Host = host
	req.Port, _ = strconv.Atoi(port)
	req.Username = parts[0]
	req.Password = parts[1]

	var bypassAuth bool

	var sb strings.Builder
	if h.PolicyTemplate != nil {
		sb.Reset()
		err := h.PolicyTemplate.Execute(&sb, struct {
			Request QuicRequest
		}{req})
		if err != nil {
			log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_policy", h.Config.ForwardPolicy).Msg("execute forward_policy error")
			return
		}

		output := strings.TrimSpace(sb.String())
		log.Debug().Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_policy_output", output).Msg("execute forward_policy ok")

		switch output {
		case "reject", "deny":
			return
		case "require_auth", "require_socks_auth":
			break
		case "bypass_auth":
			bypassAuth = true
		}
	}

	var ai QuicAuthInfo
	if h.AuthTemplate != nil && !bypassAuth {
		ai, err = h.GetAuthInfo(req)
		if err != nil {
			log.Warn().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Msg("auth error")
			return
		}
	}
	if !ai.VIP {
		if s, err := publicsuffix.EffectiveTLDPlusOne(req.Host); err == nil {
			if !h.AllowDomains.Empty() && !h.AllowDomains.Contains(s) {
				return
			}
			if h.DenyDomains.Contains(s) {
				return
			}
		}
		if ai.SpeedLimit == 0 && h.Config.ForwardSpeedLimit > 0 {
			ai.SpeedLimit = h.Config.ForwardSpeedLimit
		}
	}

	log.Info().Str("remote_ip", req.RemoteIP).Str("server_addr", req.ServerAddr).Str("username", req.Username).Str("dtls_host", req.Host).Msg("forward psk request")

	var upstream = ""
	var dail DialFunc = h.LocalDialer.DialContext
	if h.UpstreamTemplate != nil {
		sb.Reset()
		err := h.UpstreamTemplate.Execute(&sb, struct {
			Request QuicRequest
		}{req})
		if err != nil {
			log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_upstream", h.Config.ForwardUpstream).Msg("execute forward_upstream error")
			return
		}

		if upstream = strings.TrimSpace(sb.String()); upstream != "" {
			tr, ok := h.Upstreams[upstream]
			if !ok {
				log.Error().Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_upstream", h.Config.ForwardUpstream).Str("upstream", upstream).Msg("upstream not exists")
				return
			}
			dail = tr.DialContext
		}
	}

	log.Info().Str("server_addr", req.ServerAddr).Str("username", req.Username).Str("remote_ip", req.RemoteIP).Str("dtls_host", req.Host).Int("dtls_port", req.Port).Str("forward_upsteam", upstream).Msg("forward psk request")

	rconn, err := dail(context.Background(), network, net.JoinHostPort(req.Host, strconv.Itoa(req.Port)))
	if err != nil {
		log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_upstream", h.Config.ForwardUpstream).Str("dtls_host", req.Host).Int("dtls_port", req.Port).Str("forward_upsteam", upstream).Msg("connect remote host failed")
		return
	}
	defer rconn.Close()

	rconn.Write(b[i+2:])
	go io.Copy(rconn, conn)
	_, err = io.Copy(conn, NewLimiterReader(rconn, ai.SpeedLimit))

	if h.Config.ForwardLog {
		var country, region, city string
		if h.RegionResolver.MaxmindReader != nil {
			country, region, city, _ = h.RegionResolver.LookupCity(context.Background(), net.ParseIP(req.RemoteIP))
		} else {
			country, _ = h.RegionResolver.LookupCountry(context.Background(), req.RemoteIP)
		}
		h.ForwardLogger.Info().Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("remote_country", country).Str("remote_region", region).Str("remote_city", city).Str("forward_upstream", h.Config.ForwardUpstream).Str("dtls_host", req.Host).Int("dtls_port", req.Port).Str("forward_upsteam", upstream).Msg("forward psk request end")
	}

	return
}

type QuicAuthInfo struct {
	Deadline   time.Time
	Username   string
	SpeedLimit int64
	VIP        bool
}

func (h *QuicHandler) GetAuthInfo(req QuicRequest) (ai QuicAuthInfo, err error) {
	var b bytes.Buffer

	err = h.AuthTemplate.Execute(&b, struct {
		Request QuicRequest
	}{req})
	if err != nil {
		log.Error().Err(err).Str("forward_auth", h.Config.ForwardAuth).Msg("execute forward_auth error")
		return
	}

	commandLine := strings.TrimSpace(b.String())
	if v, ok := h.AuthCache.Get(commandLine); ok {
		ai = v.(QuicAuthInfo)
		if ai.Deadline.After(timeNow()) {
			return
		}
		h.AuthCache.Delete(commandLine)
	}

	var command string
	var arguments []string
	command, arguments, err = SplitCommandLine(commandLine)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	b.Reset()
	cmd := exec.CommandContext(ctx, command, arguments...)
	cmd.Stdout = &b
	cmd.Stderr = &b

	err = cmd.Run()
	if err != nil {
		log.Warn().Strs("cmd_args", cmd.Args).Bytes("output", b.Bytes()).Str("remote_ip", req.RemoteIP).Err(err).Msg("exec.Command(...) error")
		return
	}

	log.Debug().Str("remote_ip", req.RemoteIP).Strs("cmd_args", cmd.Args).Bytes("output", b.Bytes()).Err(err).Msg("exec.Command() ok")

	var p fastjson.Parser
	var doc *fastjson.Value
	doc, err = p.ParseBytes(b.Bytes())
	if err != nil {
		return
	}

	if v := doc.GetStringBytes("username"); len(v) != 0 {
		ai.Username = string(v)
	}
	if v := doc.GetInt("speedlimit"); v > 0 {
		ai.SpeedLimit = int64(v)
	}
	if v := doc.GetInt("vip"); v != 0 {
		ai.VIP = true
	}
	if v := doc.GetStringBytes("error"); len(v) != 0 {
		err = errors.New(string(v))
	}
	if ttl := doc.GetInt("ttl"); ttl > 0 && err == nil {
		ai.Deadline = timeNow().Add(time.Duration(ttl) * time.Second)
		h.AuthCache.Set(commandLine, ai)
	}

	return
}
