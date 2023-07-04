package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type HTTPConfig struct {
	Listen         []string          `json:"listen" yaml:"listen"`
	ServerName     []string          `json:"server_name" yaml:"server_name"`
	Keyfile        string            `json:"keyfile" yaml:"keyfile"`
	Certfile       string            `json:"certfile" yaml:"certfile"`
	DisableHttp2   bool              `json:"disable_http2" yaml:"disable_http2"`
	DisableHttp3   bool              `json:"disable_http3" yaml:"disable_http3"`
	DisableTls11   bool              `json:"disable_tls11" yaml:"disable_tls11"`
	PreferChacha20 bool              `json:"perfer_chacha20" yaml:"perfer_chacha20"`
	Mimes          map[string]string `json:"mimes" yaml:"mimes"`
	Forward        struct {
		Policy           string `json:"policy" yaml:"policy"`
		AuthTable        string `json:"auth_table" yaml:"auth_table"`
		Upstream         string `json:"upstream" yaml:"upstream"`
		DenyDomainsTable string `json:"deny_domains_table" yaml:"deny_domains_table"`
		SpeedLimit       int64  `json:"speed_limit" yaml:"speed_limit"`
		BindInterface    string `json:"bind_interface" yaml:"bind_interface"`
		PreferIpv6       bool   `json:"prefer_ipv6" yaml:"prefer_ipv6"`
		Log              bool   `json:"log" yaml:"log"`
	} `json:"forward" yaml:"forward"`
	Web []struct {
		Location string `json:"location" yaml:"location"`
		Index    struct {
			Root    string `json:"root" yaml:"root"`
			Headers string `json:"headers" yaml:"headers"`
			Body    string `json:"body" yaml:"body"`
			Fcgi    struct {
				Enabled bool   `json:"enabled" yaml:"enabled"`
				Pass    string `json:"pass" yaml:"pass"`
			} `json:"fcgi" yaml:"fcgi"`
		} `json:"index" yaml:"index"`
		Dav struct {
			Enabled           bool   `json:"enabled" yaml:"enabled"`
			Root              string `json:"root" yaml:"root"`
			AuthBasic         string `json:"auth_basic" yaml:"auth_basic"`
			AuthBasicUserFile string `json:"auth_basic_user_file" yaml:"auth_basic_user_file"`
		} `json:"dav" yaml:"dav"`
		Proxy struct {
			Pass              string `json:"pass" yaml:"pass"`
			AuthBasic         string `json:"auth_basic" yaml:"auth_basic"`
			AuthBasicUserFile string `json:"auth_basic_user_file" yaml:"auth_basic_user_file"`
			SetHeaders        string `json:"set_headers" yaml:"set_headers"`
			DumpFailure       bool   `json:"dump_failure" yaml:"dump_failure"`
		} `json:"proxy" yaml:"proxy"`
		Pprof struct {
			Enabled bool `json:"enabled" yaml:"enabled"`
		} `json:"pprof" yaml:"pprof"`
		Pac struct {
			Enabled bool `json:"enabled" yaml:"enabled"`
		} `json:"pac" yaml:"pac"`
	} `json:"web" yaml:"web"`
}

type SocksConfig struct {
	Listen  []string `json:"listen" yaml:"listen"`
	Forward struct {
		Policy           string `json:"policy" yaml:"policy"`
		AuthTable        string `json:"auth_table" yaml:"auth_table"`
		Upstream         string `json:"upstream" yaml:"upstream"`
		DenyDomainsTable string `json:"deny_domains_table" yaml:"deny_domains_table"`
		SpeedLimit       int64  `json:"speed_limit" yaml:"speed_limit"`
		BindInterface    string `json:"bind_interface" yaml:"bind_interface"`
		PreferIpv6       bool   `json:"prefer_ipv6" yaml:"prefer_ipv6"`
		Log              bool   `json:"log" yaml:"log"`
	} `json:"forward" yaml:"forward"`
}

type RelayConfig struct {
	Listen     []string `json:"listen" yaml:"listen"`
	To         string   `json:"to" yaml:"to"`
	Upstream   string   `json:"upstream" yaml:"upstream"`
	SpeedLimit int64    `json:"speed_limit" yaml:"speed_limit"`
	Log        bool     `json:"log" yaml:"log"`
}

type Config struct {
	Global struct {
		LogLevel         string `json:"log_level" yaml:"log_level"`
		LogBackups       int    `json:"log_backups" yaml:"log_backups"`
		LogMaxsize       int64  `json:"log_maxsize" yaml:"log_maxsize"`
		LogLocaltime     bool   `json:"log_localtime" yaml:"log_localtime"`
		DenyLocalLAN     bool   `json:"deny_local_lan" yaml:"deny_local_lan"`
		DialTimeout      int    `json:"dial_timeout" yaml:"dial_timeout"`
		TcpFastopen      bool   `json:"tcp_fastopen" yaml:"tcp_fastopen"`
		DnsServer        string `json:"dns_server" yaml:"dns_server"`
		DnsCacheDuration string `json:"dns_cache_duration" yaml:"dns_cache_duration"`
		IdleConnTimeout  int    `json:"idle_conn_timeout" yaml:"idle_conn_timeout"`
		MaxIdleConns     int    `json:"max_idle_conns" yaml:"max_idle_conns"`
		GracefulTimeout  int    `json:"graceful_timeout" yaml:"graceful_timeout"`
		DatabaseSource   string `json:"database_source" yaml:"database_source"`
	} `json:"global" yaml:"global"`
	Cron []struct {
		Spec    string `json:"spec" yaml:"spec"`
		Command string `json:"command" yaml:"command"`
	} `json:"cron" yaml:"cron"`
	Upstream map[string]string `json:"upstream" yaml:"upstream"`
	Https    []HTTPConfig      `json:"https" yaml:"https"`
	Http     []HTTPConfig      `json:"http" yaml:"http"`
	Socks    []SocksConfig     `json:"socks" yaml:"socks"`
	Relay    []RelayConfig     `json:"relay" yaml:"relay"`
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
