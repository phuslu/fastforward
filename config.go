package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

type HTTPConfig struct {
	Listen       []string `json:"listen" yaml:"listen" toml:"listen"`
	ServerName   []string `json:"server_name" yaml:"server_name" toml:"server_name"`
	Keyfile      string   `json:"keyfile" yaml:"keyfile" toml:"keyfile"`
	Certfile     string   `json:"certfile" yaml:"certfile" toml:"certfile"`
	ServerConfig map[string]struct {
		Keyfile        string `json:"keyfile" yaml:"keyfile" toml:"keyfile"`
		Certfile       string `json:"certfile" yaml:"certfile" toml:"certfile"`
		DisableHttp2   bool   `json:"disable_http2" yaml:"disable_http2" toml:"disable_http2"`
		DisableHttp3   bool   `json:"disable_http3" yaml:"disable_http3" toml:"disable_http3"`
		DisableTls11   bool   `json:"disable_tls11" yaml:"disable_tls11" toml:"disable_tls11"`
		PreferChacha20 bool   `json:"perfer_chacha20" yaml:"perfer_chacha20" toml:"perfer_chacha20"`
	} `json:"server_config" yaml:"server_config" toml:"server_config"`
	Sniproxy []struct {
		ServerName  string `json:"server_name" yaml:"server_name" toml:"server_name"`
		ProxyPass   string `json:"proxy_pass" yaml:"proxy_pass" toml:"proxy_pass"`
		DialTimeout int    `json:"dial_timeout" yaml:"dial_timeout" toml:"dial_timeout"`
	} `json:"sniproxy" yaml:"sniproxy" toml:"sniproxy"`
	Forward struct {
		Policy           string `json:"policy" yaml:"policy" toml:"policy"`
		AuthTable        string `json:"auth_table" yaml:"auth_table" toml:"auth_table"`
		Dialer           string `json:"dialer" yaml:"dialer" toml:"dialer"`
		DenyDomainsTable string `json:"deny_domains_table" yaml:"deny_domains_table" toml:"deny_domains_table"`
		SpeedLimit       int64  `json:"speed_limit" yaml:"speed_limit" toml:"speed_limit"`
		PreferIpv6       bool   `json:"prefer_ipv6" yaml:"prefer_ipv6" toml:"prefer_ipv6"`
		Websocket        string `json:"websocket" yaml:"websocket" toml:"websocket"`
		Log              bool   `json:"log" yaml:"log" toml:"log"`
		LogInterval      int64  `json:"log_interval" yaml:"log_interval" toml:"log_interval"`
	} `json:"forward" yaml:"forward" toml:"forward"`
	Web []struct {
		Location string `json:"location" yaml:"location" toml:"location"`
		Cgi      struct {
			Enabled    bool   `json:"enabled" yaml:"enabled" toml:"enabled"`
			Root       string `json:"root" yaml:"root" toml:"root"`
			DefaultAPP string `json:"default_app" yaml:"default_app" toml:"default_app"`
		} `json:"cgi" yaml:"cgi" toml:"cgi"`
		Dav struct {
			Enabled           bool   `json:"enabled" yaml:"enabled" toml:"enabled"`
			Root              string `json:"root" yaml:"root" toml:"root"`
			AuthBasicUserFile string `json:"auth_basic_user_file" yaml:"auth_basic_user_file" toml:"auth_basic_user_file"`
		} `json:"dav" yaml:"dav" toml:"dav"`
		Index struct {
			Root    string `json:"root" yaml:"root" toml:"root"`
			Headers string `json:"headers" yaml:"headers" toml:"headers"`
			Body    string `json:"body" yaml:"body" toml:"body"`
			File    string `json:"file" yaml:"file" toml:"file"`
		} `json:"index" yaml:"index" toml:"index"`
		Proxy struct {
			Pass              string `json:"pass" yaml:"pass" toml:"pass"`
			AuthBasicUserFile string `json:"auth_basic_user_file" yaml:"auth_basic_user_file" toml:"auth_basic_user_file"`
			SetHeaders        string `json:"set_headers" yaml:"set_headers" toml:"set_headers"`
			DumpFailure       bool   `json:"dump_failure" yaml:"dump_failure" toml:"dump_failure"`
		} `json:"proxy" yaml:"proxy" toml:"proxy"`
	} `json:"web" yaml:"web" toml:"web"`
}

type SocksConfig struct {
	Listen  []string `json:"listen" yaml:"listen" toml:"listen"`
	Forward struct {
		Policy           string `json:"policy" yaml:"policy" toml:"policy"`
		AuthTable        string `json:"auth_table" yaml:"auth_table" toml:"auth_table"`
		Dialer           string `json:"dialer" yaml:"dialer" toml:"dialer"`
		DenyDomainsTable string `json:"deny_domains_table" yaml:"deny_domains_table" toml:"deny_domains_table"`
		SpeedLimit       int64  `json:"speed_limit" yaml:"speed_limit" toml:"speed_limit"`
		PreferIpv6       bool   `json:"prefer_ipv6" yaml:"prefer_ipv6" toml:"prefer_ipv6"`
		Log              bool   `json:"log" yaml:"log" toml:"log"`
	} `json:"forward" yaml:"forward" toml:"forward"`
}

type StreamConfig struct {
	Listen      []string `json:"listen" yaml:"listen" toml:"listen"`
	Keyfile     string   `json:"keyfile" yaml:"keyfile" toml:"keyfile"`
	Certfile    string   `json:"certfile" yaml:"certfile" toml:"certfile"`
	ProxyPass   string   `json:"proxy_pass" yaml:"proxy_pass" toml:"proxy_pass"`
	DialTimeout int      `json:"dial_timeout" yaml:"dial_timeout" toml:"dial_timeout"`
	Dialer      string   `json:"dialer" yaml:"dialer" toml:"dialer"`
	SpeedLimit  int64    `json:"speed_limit" yaml:"speed_limit" toml:"speed_limit"`
	Log         bool     `json:"log" yaml:"log" toml:"log"`
}

type SSHTunConfig struct {
	DialTimeout int    `json:"dial_timeout" yaml:"dial_timeout" toml:"dial_timeout"`
	LocalAddr   string `json:"local_addr" yaml:"local_addr" toml:"local_addr"`
	RemoteAddr  string `json:"remote_addr" yaml:"remote_addr" toml:"remote_addr"`
	SSH         struct {
		Host     string `json:"host" yaml:"host" toml:"host"`
		Port     int    `json:"port" yaml:"port" toml:"port"`
		User     string `json:"user" yaml:"user" toml:"user"`
		Password string `json:"password" yaml:"password" toml:"password"`
		Key      string `json:"key" yaml:"key" toml:"key"`
	} `json:"ssh" yaml:"ssh" toml:"ssh"`
}

type Config struct {
	Global struct {
		LogLevel        string `json:"log_level" yaml:"log_level" toml:"log_level"`
		LogBackups      int    `json:"log_backups" yaml:"log_backups" toml:"log_backups"`
		LogMaxsize      int64  `json:"log_maxsize" yaml:"log_maxsize" toml:"log_maxsize"`
		LogLocaltime    bool   `json:"log_localtime" yaml:"log_localtime" toml:"log_localtime"`
		ForbidLocalAddr bool   `json:"forbid_local_addr" yaml:"forbid_local_addr" toml:"forbid_local_addr"`
		DialTimeout     int    `json:"dial_timeout" yaml:"dial_timeout" toml:"dial_timeout"`
		// see https://issues.apache.org/jira/browse/KAFKA-16496
		DialReadBuffer   int    `json:"dial_read_buffer" yaml:"dial_read_buffer" toml:"dial_read_buffer"`
		DialWriteBuffer  int    `json:"dial_write_buffer" yaml:"dial_write_buffer" toml:"dial_write_buffer"`
		DnsServer        string `json:"dns_server" yaml:"dns_server" toml:"dns_server"`
		DnsCacheDuration string `json:"dns_cache_duration" yaml:"dns_cache_duration" toml:"dns_cache_duration"`
		IdleConnTimeout  int    `json:"idle_conn_timeout" yaml:"idle_conn_timeout" toml:"idle_conn_timeout"`
		MaxIdleConns     int    `json:"max_idle_conns" yaml:"max_idle_conns" toml:"max_idle_conns"`
		TcpBrutalRate    uint64 `json:"tcp_brutal_rate" yaml:"tcp_brutal_rate" toml:"tcp_brutal_rate"`
	} `json:"global" yaml:"global" toml:"global"`
	Cron []struct {
		Spec    string `json:"spec" yaml:"spec" toml:"spec"`
		Command string `json:"command" yaml:"command" toml:"command"`
	} `json:"cron" yaml:"cron" toml:"cron"`
	Dialer map[string]string `json:"dialer" yaml:"dialer" toml:"dialer"`
	Https  []HTTPConfig      `json:"https" yaml:"https" toml:"https"`
	Http   []HTTPConfig      `json:"http" yaml:"http" toml:"http"`
	Socks  []SocksConfig     `json:"socks" yaml:"socks" toml:"socks"`
	SSHTun []SSHTunConfig    `json:"sshtun" yaml:"sshtun" toml:"sshtun"`
	Stream []StreamConfig    `json:"stream" yaml:"stream" toml:"stream"`
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
	case ".toml":
		err = toml.Unmarshal(data, c)
	default:
		err = fmt.Errorf("format of %s not supportted", filename)
	}
	if err != nil {
		return nil, fmt.Errorf("config decode(%#v) error: %w", filename, err)
	}

	if filename == "development.yaml" {
		fmt.Fprintf(os.Stderr, "%s WAN 1 config.go:122 > liner is running in the development mode.\n", timeNow().Format("15:04:05"))
	}

	return c, nil
}
