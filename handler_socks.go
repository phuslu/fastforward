package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/template"

	"github.com/jszwec/csvutil"
	"github.com/phuslu/log"
	"golang.org/x/crypto/bcrypt"
)

type SocksRequest struct {
	RemoteAddr  string
	RemoteIP    string
	ServerAddr  string
	Version     SocksVersion
	ConnectType SocksCommand
	SupportAuth bool
	Username    string
	Password    string
	Host        string
	Port        int
	TraceID     log.XID
}

type SocksHandler struct {
	Config         SocksConfig
	ForwardLogger  log.Logger
	RegionResolver *RegionResolver
	LocalDialer    *LocalDialer
	Upstreams      map[string]Dialer
	Functions      template.FuncMap

	PolicyTemplate   *template.Template
	UpstreamTemplate *template.Template
}

func (h *SocksHandler) Load() error {
	var err error

	if s := h.Config.Forward.Policy; s != "" {
		if h.PolicyTemplate, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	if s := h.Config.Forward.Dialer; s != "" {
		if h.UpstreamTemplate, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	return nil
}

func (h *SocksHandler) ServeConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	var req SocksRequest
	req.RemoteAddr = conn.RemoteAddr().String()
	req.RemoteIP, _, _ = net.SplitHostPort(req.RemoteAddr)
	req.ServerAddr = conn.LocalAddr().String()
	req.TraceID = log.NewXID()

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

	var ai ForwardAuthInfo
	if h.Config.Forward.AuthTable != "" {
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
		ai, err = h.GetAuthInfo(req)
		if err != nil || ai.Username != req.Username {
			log.Warn().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Int("socks_version", int(req.Version)).Msg("auth error")
			conn.Write([]byte{VersionSocks5, byte(Socks5StatusGeneralFailure)})
			return
		}
	}

	// auth ok
	n, err = conn.Write([]byte{VersionSocks5, Socks5AuthMethodNone})
	if err != nil || n == 0 {
		log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_policy", h.Config.Forward.Policy).Msg("socks write auth error")
		return
	}

	n, err = io.ReadAtLeast(conn, b[:], 8)
	if (err != nil && !strings.HasSuffix(err.Error(), " EOF")) || n == 0 {
		log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_policy", h.Config.Forward.Policy).Msg("socks read address error")
		return
	}

	req.ConnectType = SocksCommand(b[1])

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

	if ai.VIP == 0 {
		if ai.SpeedLimit == 0 && h.Config.Forward.SpeedLimit > 0 {
			ai.SpeedLimit = h.Config.Forward.SpeedLimit
		}
	}

	var sb strings.Builder

	if h.PolicyTemplate != nil {
		sb.Reset()
		err := h.PolicyTemplate.Execute(&sb, struct {
			Request    SocksRequest
			ServerAddr string
		}{req, req.ServerAddr})
		if err != nil {
			log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_policy", h.Config.Forward.Policy).Msg("execute forward_policy error")
			return
		}

		output := strings.TrimSpace(sb.String())
		log.Debug().Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Interface("request", req).Str("forward_policy_output", output).Msg("execute forward_policy ok")

		switch output {
		case "reject", "deny":
			WriteSocks5Status(conn, Socks5StatusConnectionNotAllowedByRuleset)
			return
		}
	}

	log.Info().Str("remote_ip", req.RemoteIP).Str("server_addr", req.ServerAddr).Int("socks_version", int(req.Version)).Str("username", req.Username).Str("socks_host", req.Host).Msg("forward socks request")

	var dialerName = ""
	dail := h.LocalDialer.DialContext
	if h.UpstreamTemplate != nil {
		sb.Reset()
		err := h.UpstreamTemplate.Execute(&sb, struct {
			Request    SocksRequest
			ServerAddr string
		}{req, req.ServerAddr})
		if err != nil {
			log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_dialer_name", h.Config.Forward.Dialer).Msg("execute forward_dialer error")
			WriteSocks5Status(conn, Socks5StatusGeneralFailure)
			return
		}

		if dialerName = strings.TrimSpace(sb.String()); dialerName != "" {
			u, ok := h.Upstreams[dialerName]
			if !ok {
				log.Error().Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("dialer_name", dialerName).Msg("dialer not exists")
				return
			}
			dail = u.DialContext
		}
	}

	network := "tcp"
	switch req.ConnectType {
	case SocksCommandConnectUDP:
		network = "udp"
	}

	log.Info().Str("server_addr", req.ServerAddr).Int("socks_version", int(req.Version)).Str("username", req.Username).Str("remote_ip", req.RemoteIP).Str("socks_network", network).Str("socks_host", req.Host).Int("socks_port", req.Port).Str("forward_dialer_name", dialerName).Msg("forward socks request")

	ctx = context.WithValue(context.Background(), DialerHTTPHeaderContextKey, http.Header{
		"X-Forwarded-For":  []string{req.RemoteIP},
		"X-Forwarded-User": []string{req.Username},
	})
	rconn, err := dail(ctx, network, net.JoinHostPort(req.Host, strconv.Itoa(req.Port)))
	if err != nil {
		log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("socks_host", req.Host).Int("socks_port", req.Port).Int("socks_version", int(req.Version)).Str("forward_dialer_name", dialerName).Msg("connect remote host failed")
		WriteSocks5Status(conn, Socks5StatusNetworkUnreachable)
		if rconn != nil {
			rconn.Close()
		}
		return
	}
	defer rconn.Close()

	WriteSocks5Status(conn, Socks5StatusRequestGranted)

	go io.Copy(rconn, conn)
	_, err = io.Copy(conn, NewRateLimitReader(rconn, ai.SpeedLimit))

	if h.Config.Forward.Log {
		var country, region, city string
		if h.RegionResolver.MaxmindReader != nil {
			country, region, city, _ = h.RegionResolver.LookupCity(context.Background(), net.ParseIP(req.RemoteIP))
		}
		h.ForwardLogger.Info().Stringer("trace_id", req.TraceID).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("remote_country", country).Str("remote_region", region).Str("remote_city", city).Str("forward_dialer_name", h.Config.Forward.Dialer).Str("socks_host", req.Host).Int("socks_port", req.Port).Int("socks_version", int(req.Version)).Str("forward_dialer_name", dialerName).Msg("forward socks request end")
	}

	return
}

func (h *SocksHandler) GetAuthInfo(req SocksRequest) (ForwardAuthInfo, error) {
	username, password := req.Username, req.Password

	var ai ForwardAuthInfo
	if !strings.HasSuffix(h.Config.Forward.AuthTable, ".csv") {
		return ai, fmt.Errorf("unsupported auth_table: %s", h.Config.Forward.AuthTable)
	}

	data, err := os.ReadFile(h.Config.Forward.AuthTable)
	if err != nil {
		return ai, err
	}

	var records []ForwardAuthInfo

	err = csvutil.Unmarshal(data, &records)
	if err != nil {
		return ai, err
	}
	if i := slices.IndexFunc(records, func(r ForwardAuthInfo) bool {
		if r.Username != username {
			return false
		}
		switch {
		case strings.HasPrefix(r.Password, "$2a$"):
			return bcrypt.CompareHashAndPassword([]byte(r.Password), []byte(password)) == nil
		default:
			return r.Password == password
		}
	}); i >= 0 {
		ai = records[i]
	}
	if ai.Username == "" {
		return ai, fmt.Errorf("wrong username='%s' or password='%s'", username, password)
	}

	return ai, nil
}

func WriteSocks5Status(conn net.Conn, status Socks5Status) (int, error) {
	return conn.Write([]byte{VersionSocks5, byte(status), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}
