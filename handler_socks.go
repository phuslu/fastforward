package main

import (
	"context"
	"database/sql"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"text/template"

	"github.com/phuslu/log"
	"golang.org/x/crypto/bcrypt"
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
	TraceID     log.XID
}

type SocksHandler struct {
	Config         SocksConfig
	ForwardLogger  log.Logger
	RegionResolver *RegionResolver
	LocalDialer    *LocalDialer
	Upstreams      map[string]Dialer
	Functions      template.FuncMap
	DB             *sql.DB

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

	if s := h.Config.Forward.Upstream; s != "" {
		if h.UpstreamTemplate, err = template.New(s).Funcs(h.Functions).Parse(s); err != nil {
			return err
		}
	}

	if h.Config.Forward.BindInterface != "" {
		if runtime.GOOS != "linux" {
			log.Fatal().Strs("server_listen", h.Config.Listen).Msg("option bind_interface is only available on linux")
		}
		if h.Config.Forward.Upstream != "" {
			log.Fatal().Strs("server_listen", h.Config.Listen).Msg("option bind_interface is confilict with option upstream")
		}

		dialer := new(LocalDialer)
		*dialer = *h.LocalDialer
		dialer.BindInterface = h.Config.Forward.BindInterface
		dialer.PreferIPv6 = h.Config.Forward.PreferIpv6

		h.LocalDialer = dialer
	}

	return nil
}

func (h *SocksHandler) ServeConn(conn net.Conn) {
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
		if addressType == Socks5DomainName && h.Config.Forward.DenyDomainsTable != "" {
			if domain, err := publicsuffix.EffectiveTLDPlusOne(req.Host); err == nil {
				err = h.DB.QueryRow("SELECT domain FROM `"+h.Config.Forward.AuthTable+"` WHERE domain=? LIMIT 1", domain).Err()
				if err != nil {
					WriteSocks5Status(conn, Socks5StatusConnectionNotAllowedByRuleset)
					return
				}
			}
		}
		if ai.SpeedLimit == 0 && h.Config.Forward.SpeedLimit > 0 {
			ai.SpeedLimit = h.Config.Forward.SpeedLimit
		}
	}

	var sb strings.Builder

	if h.PolicyTemplate != nil {
		sb.Reset()
		err := h.PolicyTemplate.Execute(&sb, struct {
			Request SocksRequest
		}{req})
		if err != nil {
			log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_policy", h.Config.Forward.Policy).Msg("execute forward_policy error")
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
	dail := h.LocalDialer.DialContext
	if h.UpstreamTemplate != nil {
		sb.Reset()
		err := h.UpstreamTemplate.Execute(&sb, struct {
			Request SocksRequest
		}{req})
		if err != nil {
			log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_upstream", h.Config.Forward.Upstream).Msg("execute forward_upstream error")
			WriteSocks5Status(conn, Socks5StatusGeneralFailure)
			return
		}

		if upstream = strings.TrimSpace(sb.String()); upstream != "" {
			u, ok := h.Upstreams[upstream]
			if !ok {
				log.Error().Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_upstream", h.Config.Forward.Upstream).Str("upstream", upstream).Msg("upstream not exists")
				return
			}
			dail = u.DialContext
		}
	}

	log.Info().Str("server_addr", req.ServerAddr).Int("socks_version", int(req.Version)).Str("username", req.Username).Str("remote_ip", req.RemoteIP).Str("socks_host", req.Host).Int("socks_port", req.Port).Str("forward_upsteam", upstream).Msg("forward socks request")

	rconn, err := dail(context.Background(), "tcp", net.JoinHostPort(req.Host, strconv.Itoa(req.Port)))
	if err != nil {
		log.Error().Err(err).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("forward_upstream", h.Config.Forward.Upstream).Str("socks_host", req.Host).Int("socks_port", req.Port).Int("socks_version", int(req.Version)).Str("forward_upsteam", upstream).Msg("connect remote host failed")
		WriteSocks5Status(conn, Socks5StatusNetworkUnreachable)
		if rconn != nil {
			rconn.Close()
		}
		return
	}
	defer rconn.Close()

	WriteSocks5Status(conn, Socks5StatusRequestGranted)

	go io.Copy(rconn, conn)
	_, err = io.Copy(conn, NewLimiterReader(rconn, ai.SpeedLimit))

	if h.Config.Forward.Log {
		var country, region, city string
		if h.RegionResolver.MaxmindReader != nil {
			country, region, city, _ = h.RegionResolver.LookupCity(context.Background(), net.ParseIP(req.RemoteIP))
		} else {
			country, _ = h.RegionResolver.LookupCountry(context.Background(), req.RemoteIP)
		}
		h.ForwardLogger.Info().Stringer("trace_id", req.TraceID).Str("server_addr", req.ServerAddr).Str("remote_ip", req.RemoteIP).Str("remote_country", country).Str("remote_region", region).Str("remote_city", city).Str("forward_upstream", h.Config.Forward.Upstream).Str("socks_host", req.Host).Int("socks_port", req.Port).Int("socks_version", int(req.Version)).Str("forward_upsteam", upstream).Msg("forward socks request end")
	}

	return
}

func (h *SocksHandler) GetAuthInfo(req SocksRequest) (ForwardAuthInfo, error) {
	username, password := req.Username, req.Password

	var ai ForwardAuthInfo
	var err error
	if strings.HasSuffix(h.Config.Forward.AuthTable, ".csv") {
		data, err := os.ReadFile(h.Config.Forward.AuthTable)
		if err != nil {
			return ai, err
		}
		records, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
		if err != nil {
			return ai, err
		}
		if len(records) < 2 || len(records[0]) < 4 || !(records[0][0] == "username" && records[0][1] == "password" && records[0][2] == "speedlimit" && records[0][3] == "vip") {
			return ai, fmt.Errorf("invaild csv records")
		}
		for _, record := range records[1:] {
			if record[0] != username {
				continue
			}
			ai.Username = record[0]
			ai.Password = record[1]
			ai.SpeedLimit, _ = strconv.ParseInt(record[2], 10, 64)
			ai.VIP, _ = strconv.Atoi(record[3])
		}
	} else {
		err = h.DB.QueryRow("SELECT username, password, speedlimit, vip FROM `"+h.Config.Forward.AuthTable+"` WHERE username=? LIMIT 1", username).Scan(&ai.Username, &ai.Password, &ai.SpeedLimit, &ai.VIP)
		if err != nil {
			return ai, err
		}
	}

	switch {
	case strings.HasPrefix(ai.Password, "$2a$"):
		err = bcrypt.CompareHashAndPassword([]byte(ai.Password), []byte(password))
	default:
		if ai.Password != password {
			err = fmt.Errorf("plain password mismatch")
		}
	}

	if err != nil {
		return ai, fmt.Errorf("wrong username='%s' or password='%s'", username, password)
	}

	return ai, nil
}

func WriteSocks5Status(conn net.Conn, status Socks5Status) (int, error) {
	return conn.Write([]byte{VersionSocks5, byte(status), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
}
