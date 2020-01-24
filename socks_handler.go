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

	"github.com/phuslu/log"
	"github.com/tidwall/shardmap"
	"github.com/valyala/fastjson"
	"golang.org/x/net/publicsuffix"
)

type SocksRequest struct {
	RemoteAddr  string
	RemoteIP    string
	ServerAddr  string
	Version     SocksVersion
	SupportAuth bool
	Username    string
	Password    string
	Host        string
	Port        int
}

type SocksHandler struct {
	Config         SocksConfig
	ForwardLogger  log.Logger
	RegionResolver *RegionResolver
	Dialer         *Dialer
	Upstreams      map[string]*http.Transport
	Functions      template.FuncMap

	AllowDomains     StringSet
	DenyDomains      StringSet
	PolicyTemplate   *template.Template
	AuthTemplate     *template.Template
	UpstreamTemplate *template.Template
	AuthCache        *shardmap.Map
}

func (h *SocksHandler) Load() error {
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

		var dialer = *h.Dialer
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(h.Config.ForwardOutboundIp)}
		dialer.Control = (DailerController{BindAddressNoPort: true}).Control
	}

	h.AuthCache = shardmap.New(0)

	return nil
}

func (h *SocksHandler) ServeConn(conn net.Conn) {
	defer conn.Close()

	var req SocksRequest
	req.RemoteAddr = conn.RemoteAddr().String()
	req.RemoteIP, _, _ = net.SplitHostPort(req.RemoteAddr)
	req.ServerAddr = conn.LocalAddr().String()

	var b [512]byte
	n, err := io.ReadAtLeast(conn, b[:], 2)
	if err != nil || n == 0 {
		log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Msg("socks read handshake error")
		return
	}

	req.Version = SocksVersion(b[0])
	for i := 0; i < int(b[1]); i++ {
		if b[i+2] == Socks5AuthMethodPassword {
			req.SupportAuth = true
			break
		}
	}

	var bypassAuth bool

	var sb strings.Builder
	if h.PolicyTemplate != nil {
		sb.Reset()
		err := h.PolicyTemplate.Execute(&sb, struct {
			Request SocksRequest
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

	var ai SocksAuthInfo
	if !bypassAuth {
		if !req.SupportAuth {
			log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Msg("socks client not support auth")
			return
		}
		conn.Write([]byte{VersionSocks5, byte(Socks5AuthMethodPassword)})
		n, err = io.ReadAtLeast(conn, b[:], 4)
		if err != nil || n == 0 {
			log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Msg("socks read auth error")
			return
		}
		// unpack username & password
		req.Username = string(b[2 : 2+int(b[1])])
		req.Password = string(b[3+int(b[1]) : 3+int(b[1])+int(b[2+int(b[1])])])
		// auth plugin
		if h.AuthTemplate != nil && !bypassAuth {
			ai, err = h.GetAuthInfo(req)
			if err != nil {
				log.Warn().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Int("socks_version", int(req.Version)).Msg("auth error")
				conn.Write([]byte{VersionSocks5, byte(Socks5StatusGeneralFailure)})
				return
			}
		}
	}

	// auth ok
	n, err = conn.Write([]byte{VersionSocks5, Socks5AuthMethodNone})
	if err != nil || n == 0 {
		log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_policy", h.Config.ForwardPolicy).Msg("socks write auth error")
		return
	}

	n, err = io.ReadAtLeast(conn, b[:], 8)
	if err != nil || n == 0 {
		log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_policy", h.Config.ForwardPolicy).Msg("socks read address error")
		return
	}

	var addressType = Socks5AddressType(b[3])
	switch addressType {
	case Socks5IPv4Address:
		req.Host = net.IP(b[4:8]).String()
	case Socks5DomainName:
		req.Host = string(b[5 : 5+int(b[4])]) //b[4]表示域名的长度
	case Socks5IPv6Address:
		req.Host = net.IP(b[4:20]).String()
	}
	req.Port = int(b[n-2])<<8 | int(b[n-1])

	if !ai.VIP {
		if addressType == Socks5DomainName && (!h.AllowDomains.Empty() || !h.DenyDomains.Empty()) {
			if s, err := publicsuffix.EffectiveTLDPlusOne(req.Host); err == nil {
				if !h.AllowDomains.Empty() && !h.AllowDomains.Contains(s) {
					WriteSocks5Status(conn, Socks5StatusConnectionNotAllowedByRuleset)
					return
				}
				if h.DenyDomains.Contains(s) {
					WriteSocks5Status(conn, Socks5StatusConnectionNotAllowedByRuleset)
					return
				}
			}
		}
	}

	if h.PolicyTemplate != nil {
		sb.Reset()
		err := h.PolicyTemplate.Execute(&sb, struct {
			Request SocksRequest
		}{req})
		if err != nil {
			log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_policy", h.Config.ForwardPolicy).Msg("execute forward_policy error")
			return
		}

		output := strings.TrimSpace(sb.String())
		log.Debug().Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_policy_output", output).Msg("execute forward_policy ok")

		switch output {
		case "reject", "deny":
			WriteSocks5Status(conn, Socks5StatusConnectionNotAllowedByRuleset)
			return
		case "require_auth", "require_socks_auth":
			// should not reach here
			WriteSocks5Status(conn, Socks5StatusConnectionNotAllowedByRuleset)
			return
		}
	}

	log.Info().Str("remote_ip", req.RemoteIP).Str("server_addr", req.ServerAddr).Int("socks_version", int(req.Version)).Str("username", req.Username).Str("socks_host", req.Host).Msg("forward socks request")

	var upstream = ""
	var dail DialFunc = h.Dialer.DialContext
	if h.UpstreamTemplate != nil {
		sb.Reset()
		err := h.UpstreamTemplate.Execute(&sb, struct {
			Request SocksRequest
		}{req})
		if err != nil {
			log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_upstream", h.Config.ForwardUpstream).Msg("execute forward_upstream error")
			WriteSocks5Status(conn, Socks5StatusGeneralFailure)
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

	log.Info().Str("server_addr", req.ServerAddr).Int("socks_version", int(req.Version)).Str("username", req.Username).Str("remote_ip", req.RemoteIP).Str("socks_host", req.Host).Int("socks_port", req.Port).Int("socks_version", int(req.Version)).Str("forward_upsteam", upstream).Msg("forward socks request")

	rconn, err := dail(context.Background(), "tcp", net.JoinHostPort(req.Host, strconv.Itoa(req.Port)))
	if err != nil {
		log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_upstream", h.Config.ForwardUpstream).Str("socks_host", req.Host).Int("socks_port", req.Port).Int("socks_version", int(req.Version)).Str("forward_upsteam", upstream).Msg("connect remote host failed")
		WriteSocks5Status(conn, Socks5StatusNetworkUnreachable)
		return
	}
	defer rconn.Close()

	WriteSocks5Status(conn, Socks5StatusRequestGranted)

	go io.Copy(rconn, conn)
	_, err = io.Copy(conn, NewLimiterReader(rconn, ai.SpeedLimit))

	if h.Config.ForwardLog {
		var country, region, city string
		if h.RegionResolver.MaxmindReader != nil {
			country, region, city, _ = h.RegionResolver.LookupCity(context.Background(), net.ParseIP(req.RemoteIP))
		} else {
			country, _ = h.RegionResolver.LookupCountry(context.Background(), req.RemoteIP)
		}
		h.ForwardLogger.Info().Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("remote_country", country).Str("remote_region", region).Str("remote_city", city).Str("forward_upstream", h.Config.ForwardUpstream).Str("socks_host", req.Host).Int("socks_port", req.Port).Int("socks_version", int(req.Version)).Str("forward_upsteam", upstream).Msg("forward socks request end")
	}

	return
}

type SocksAuthInfo struct {
	Deadline   time.Time
	Username   string
	SpeedLimit int64
	VIP        bool
}

func (h *SocksHandler) GetAuthInfo(req SocksRequest) (ai SocksAuthInfo, err error) {
	var b bytes.Buffer

	err = h.AuthTemplate.Execute(&b, struct {
		Request SocksRequest
	}{req})
	if err != nil {
		log.Error().Err(err).Str("forward_auth", h.Config.ForwardAuth).Msg("execute forward_auth error")
		return
	}

	commandLine := strings.TrimSpace(b.String())
	if v, ok := h.AuthCache.Get(commandLine); ok {
		ai = v.(SocksAuthInfo)
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

func WriteSocks5Status(conn net.Conn, status Socks5Status) (int, error) {
	return conn.Write([]byte{VersionSocks5, byte(status), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}
