package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type HTTPConfig struct {
	Listen         []string          `json yaml:"listen"`
	ServerName     []string          `json yaml:"server_name"`
	Keyfile        string            `json yaml:"keyfile"`
	Certfile       string            `json yaml:"certfile"`
	DisableHttp2   bool              `json yaml:"disable_http2"`
	PreferChacha20 bool              `json yaml:"perfer_chacha20"`
	Mimes          map[string]string `json yaml:"mimes"`
	Forward        struct {
		Policy       string   `json yaml:"policy"`
		Auth         string   `json yaml:"auth"`
		Upstream     string   `json yaml:"upstream"`
		AllowDomains []string `json yaml:"allow_domains"`
		DenyDomains  []string `json yaml:"deny_domains"`
		SpeedLimit   int64    `json yaml:"speed_limit"`
		OutboundIp   string   `json yaml:"outbound_ip"`
		Log          bool     `json yaml:"log"`
	} `json yaml:"forward"`
	Web []struct {
		Location string `json yaml:"location"`
		Index    struct {
			Root    string `json yaml:"root"`
			Headers string `json yaml:"headers"`
			Body    string `json yaml:"body"`
			Webdav  bool   `json yaml:"webdav"`
		} `json yaml:"index"`
		Proxy struct {
			Pass        string `json yaml:"pass"`
			SetHeaders  string `json yaml:"set_headers"`
			DumpFailure bool   `json yaml:"dump_failure"`
		} `json yaml:"proxy"`
		Pprof struct {
			Enabled bool `json yaml:"enabled"`
		} `json yaml:"pprof"`
		Pac struct {
			Enabled bool `json yaml:"enabled"`
		} `json yaml:"pac"`
		Doh struct {
			Enabled  bool                `json yaml:"enabled"`
			Upstream string              `json yaml:"upstream"`
			Prelude  map[string][]string `json yaml:"prelude"`
		} `json yaml:"doh"`
	} `json yaml:"web"`
}

type SocksConfig struct {
	Listen  []string `json yaml:"listen"`
	Forward struct {
		Policy       string   `json yaml:"policy"`
		Auth         string   `json yaml:"auth"`
		Upstream     string   `json yaml:"upstream"`
		AllowDomains []string `json yaml:"allow_domain"`
		DenyDomains  []string `json yaml:"deny_domains"`
		SpeedLimit   int64    `json yaml:"speed_limit"`
		OutboundIp   string   `json yaml:"outbound_ip"`
		Log          bool     `json yaml:"log"`
	} `json yaml:"forward"`
}

type RelayConfig struct {
	Listen     []string `json yaml:"listen"`
	To         string   `json yaml:"to"`
	Upstream   string   `json yaml:"upstream"`
	SpeedLimit int64    `json yaml:"speed_limit"`
	Log        bool     `json yaml:"log"`
}

type DNSConfig struct {
	Listen   []string `json yaml:"listen"`
	Upstream []string `json yaml:"upstream"`
}

type Config struct {
	Log struct {
		Level     string `json yaml:"level"`
		Backups   int    `json yaml:"backups"`
		Maxsize   int64  `json yaml:"maxsize"`
		Localtime bool   `json yaml:"localtime"`
	} `json yaml:"log"`
	Global struct {
		DenyIntranet    bool   `json yaml:"deny_intranet"`
		DialTimeout     int    `json yaml:"dial_timeout"`
		TcpFastopen     bool   `json yaml:"tcp_fastopen"`
		PreferIpv6      bool   `json yaml:"perfer_ipv6"`
		DnsServer       string `json yaml:"dns_server"`
		DnsTtl          uint32 `json yaml:"dns_ttl"`
		IdleConnTimeout int    `json yaml:"idle_conn_timeout"`
		MaxIdleConns    int    `json yaml:"max_idle_conns"`
		GracefulTimeout int    `json yaml:"graceful_timeout"`
	} `json yaml:"global"`
	Cron []struct {
		Spec    string `json yaml:"spec"`
		Command string `json yaml:"command"`
	} `json yaml:"cron"`
	Https    []HTTPConfig  `json yaml:"https"`
	Http     []HTTPConfig  `json yaml:"http"`
	Socks    []SocksConfig `json yaml:"socks"`
	Relay    []RelayConfig `json yaml:"relay"`
	Dns      []DNSConfig   `json yaml:"dns"`
	Upstream map[string]struct {
		Scheme    string `json yaml:"scheme"`
		Username  string `json yaml:"username"`
		Password  string `json yaml:"password"`
		Host      string `json yaml:"host"`
		Port      int    `json yaml:"port"`
		UserAgent string `json yaml:"user_agent"`
	} `json yaml:"upstream"`
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

	data, err := ioutil.ReadFile(filename)
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
