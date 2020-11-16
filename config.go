package main

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/naoina/toml"
)

type HTTPConfig struct {
	Listen         []string
	ServerName     []string
	Keyfile        string
	Certfile       string
	DisableHttp2   bool
	PreferChacha20 bool

	ForwardPolicy       string
	ForwardAuth         string
	ForwardUpstream     string
	ForwardAllowDomains []string
	ForwardDenyDomains  []string
	ForwardSpeedLimit   int64
	ForwardOutboundIp   string
	ForwardLog          bool

	PacEnabled   bool
	PprofEnabled bool

	ProxyPass        string
	ProxySetHeaders  map[string]string
	ProxyDumpFailure bool

	StaticRoot         string
	StaticTemplate     string
	StaticCharset      string
	StaticAddAfterBody string
}

type SocksConfig struct {
	Listen []string

	ForwardPolicy       string
	ForwardAuth         string
	ForwardUpstream     string
	ForwardAllowDomains []string
	ForwardDenyDomains  []string
	ForwardSpeedLimit   int64
	ForwardOutboundIp   string
	ForwardLog          bool
}

type RelayConfig struct {
	Listen []string

	RelayTo           string
	ForwardUpstream   string
	ForwardSpeedLimit int64
	ForwardLog        bool
}

type DNSConfig struct {
	Listen []string

	Upstream []string
}

type Config struct {
	raw []byte
	Log struct {
		Level     string
		Backups   int
		Maxsize   int64
		Localtime bool
	}
	Global struct {
		DenyIntranet    bool
		DialTimeout     int
		TcpFastopen     bool
		PreferIpv6      bool
		DnsServer       string
		DnsTtl          uint32
		IdleConnTimeout int
		MaxIdleConns    int
		GracefulTimeout int
	}
	Cron []struct {
		Spec    string
		Command string
	}
	Https    []HTTPConfig
	Http     []HTTPConfig
	Socks    []SocksConfig
	Relay    []RelayConfig
	Dns      []DNSConfig
	Upstream map[string]struct {
		Scheme    string
		Username  string
		Password  string
		Host      string
		Port      int
		UserAgent string
	}
}

func NewConfig(filename string) (*Config, error) {
	if filename == "" {
		var env = "development"
		for _, name := range []string{"GOLANG_ENV", "ENV"} {
			if s := os.Getenv(name); s != "" {
				env = s
				break
			}
		}
		filename = env + ".toml"
	}

	tomlData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	c := new(Config)
	if err = toml.Unmarshal(tomlData, c); err != nil {
		return nil, fmt.Errorf("toml.Decode(%#v) error: %+v", filename, err)
	}

	if filename == "development.toml" {
		fmt.Fprintf(os.Stderr, "%s WAN 1 config.go:122 > liner is running in the development mode.\n", timeNow().Format("15:04:05"))
	}

	c.raw = tomlData

	return c, nil
}
