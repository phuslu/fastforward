package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

type HTTPConfig struct {
	Listen       []string `json:"listen" yaml:"listen"`
	ServerName   []string `json:"server_name" yaml:"server_name"`
	ServerConfig map[string]struct {
		Keyfile        string `json:"keyfile" yaml:"keyfile"`
		Certfile       string `json:"certfile" yaml:"certfile"`
		DisableHttp2   bool   `json:"disable_http2" yaml:"disable_http2"`
		DisableHttp3   bool   `json:"disable_http3" yaml:"disable_http3"`
		DisableTls11   bool   `json:"disable_tls11" yaml:"disable_tls11"`
		PreferChacha20 bool   `json:"perfer_chacha20" yaml:"perfer_chacha20"`
	} `json:"server_config" yaml:"server_config"`
	Sniproxy []struct {
		ServerName  string `json:"server_name" yaml:"server_name"`
		ProxyPass   string `json:"proxy_pass" yaml:"proxy_pass"`
		DialTimeout int    `json:"dial_timeout" yaml:"dial_timeout"`
	} `json:"sniproxy" yaml:"sniproxy"`
	Forward struct {
		Policy           string `json:"policy" yaml:"policy"`
		AuthTable        string `json:"auth_table" yaml:"auth_table"`
		Dialer           string `json:"dialer" yaml:"dialer"`
		DenyDomainsTable string `json:"deny_domains_table" yaml:"deny_domains_table"`
		SpeedLimit       int64  `json:"speed_limit" yaml:"speed_limit"`
		BindInterface    string `json:"bind_interface" yaml:"bind_interface"`
		PreferIpv6       bool   `json:"prefer_ipv6" yaml:"prefer_ipv6"`
		Websocket        string `json:"websocket" yaml:"websocket"`
		Log              bool   `json:"log" yaml:"log"`
	} `json:"forward" yaml:"forward"`
	Web []struct {
		Location string `json:"location" yaml:"location"`
		Index    struct {
			Root    string `json:"root" yaml:"root"`
			Headers string `json:"headers" yaml:"headers"`
			Body    string `json:"body" yaml:"body"`
		} `json:"index" yaml:"index"`
		Dav struct {
			Enabled           bool   `json:"enabled" yaml:"enabled"`
			Root              string `json:"root" yaml:"root"`
			AuthBasicUserFile string `json:"auth_basic_user_file" yaml:"auth_basic_user_file"`
		} `json:"dav" yaml:"dav"`
		Proxy struct {
			Pass              string `json:"pass" yaml:"pass"`
			AuthBasicUserFile string `json:"auth_basic_user_file" yaml:"auth_basic_user_file"`
			SetHeaders        string `json:"set_headers" yaml:"set_headers"`
			DumpFailure       bool   `json:"dump_failure" yaml:"dump_failure"`
		} `json:"proxy" yaml:"proxy"`
		Pprof struct {
			Enabled bool `json:"enabled" yaml:"enabled"`
		} `json:"pprof" yaml:"pprof"`
	} `json:"web" yaml:"web"`
}

type SocksConfig struct {
	Listen  []string `json:"listen" yaml:"listen"`
	Forward struct {
		Policy           string `json:"policy" yaml:"policy"`
		AuthTable        string `json:"auth_table" yaml:"auth_table"`
		Dialer           string `json:"dialer" yaml:"dialer"`
		DenyDomainsTable string `json:"deny_domains_table" yaml:"deny_domains_table"`
		SpeedLimit       int64  `json:"speed_limit" yaml:"speed_limit"`
		BindInterface    string `json:"bind_interface" yaml:"bind_interface"`
		PreferIpv6       bool   `json:"prefer_ipv6" yaml:"prefer_ipv6"`
		Log              bool   `json:"log" yaml:"log"`
	} `json:"forward" yaml:"forward"`
}

type StreamConfig struct {
	Listen      []string `json:"listen" yaml:"listen"`
	Keyfile     string   `json:"keyfile" yaml:"keyfile"`
	Certfile    string   `json:"certfile" yaml:"certfile"`
	ProxyPass   string   `json:"proxy_pass" yaml:"proxy_pass"`
	DialTimeout int      `json:"dial_timeout" yaml:"dial_timeout"`
	Dialer      string   `json:"dialer" yaml:"dialer"`
	SpeedLimit  int64    `json:"speed_limit" yaml:"speed_limit"`
	Log         bool     `json:"log" yaml:"log"`
}

type TunnelConfig struct {
	Server struct {
		Listen string `json:"listen" yaml:"listen"`
		Key    string `json:"key" yaml:"key"`
	} `json:"server" yaml:"server"`
	Client struct {
		RemoteAddr string `json:"remote_addr" yaml:"remote_addr"`
		LocalAddr  string `json:"local_addr" yaml:"local_addr"`
		Key        string `json:"key" yaml:"key"`
	} `json:"client" yaml:"client"`
}

type Config struct {
	Global struct {
		LogLevel         string `json:"log_level" yaml:"log_level"`
		LogBackups       int    `json:"log_backups" yaml:"log_backups"`
		LogMaxsize       int64  `json:"log_maxsize" yaml:"log_maxsize"`
		LogLocaltime     bool   `json:"log_localtime" yaml:"log_localtime"`
		ForbidLocalAddr  bool   `json:"forbid_local_addr" yaml:"forbid_local_addr"`
		DialTimeout      int    `json:"dial_timeout" yaml:"dial_timeout"`
		DialReadBuffer   int    `json:"dial_read_buffer" yaml:"dial_read_buffer"`
		DialWriteBuffer  int    `json:"dial_write_buffer" yaml:"dial_write_buffer"`
		DnsServer        string `json:"dns_server" yaml:"dns_server"`
		DnsCacheDuration string `json:"dns_cache_duration" yaml:"dns_cache_duration"`
		IdleConnTimeout  int    `json:"idle_conn_timeout" yaml:"idle_conn_timeout"`
		MaxIdleConns     int    `json:"max_idle_conns" yaml:"max_idle_conns"`
	} `json:"global" yaml:"global"`
	Cron []struct {
		Spec    string `json:"spec" yaml:"spec"`
		Command string `json:"command" yaml:"command"`
	} `json:"cron" yaml:"cron"`
	Dialer map[string]string `json:"dialer" yaml:"dialer"`
	Https  []HTTPConfig      `json:"https" yaml:"https"`
	Http   []HTTPConfig      `json:"http" yaml:"http"`
	Socks  []SocksConfig     `json:"socks" yaml:"socks"`
	Stream []StreamConfig    `json:"stream" yaml:"stream"`
	Tunnel []TunnelConfig    `json:"tunnel" yaml:"tunnel"`
}

func NewConfig(filename string) (*Config, error) {
	if filename == "" {
		var env = "development"
		// perfer GOLANG_ENV
		for _, name := range []string{"GOLANG_ENV", "ENV"} {
			if s := os.Getenv(name); s != "" {
				env = s
				break
			}
		}
		// perfer .json
		for _, ext := range []string{".json", ".yaml"} {
			filename = env + ext
			if _, err := os.Stat(filename); err == nil {
				break
			}
		}
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	data = regexp.MustCompilePOSIX(`^( *)upstream:`).ReplaceAll(data, []byte("${1}dialer:"))

	c := new(Config)
	switch filepath.Ext(filename) {
	case ".json":
		err = json.Unmarshal(data, c)
	case ".yaml":
		err = yaml.Unmarshal(data, c)
	default:
		err = fmt.Errorf("format of %s not supportted", filename)
	}
	if err != nil {
		return nil, fmt.Errorf("yaml.Decode(%#v) error: %w", filename, err)
	}

	if filename == "development.yaml" {
		fmt.Fprintf(os.Stderr, "%s WAN 1 config.go:122 > liner is running in the development mode.\n", timeNow().Format("15:04:05"))
	}

	return c, nil
}
