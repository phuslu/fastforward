package main

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var _ Dialer = (*SSHDialer)(nil)

type SSHDialer struct {
	Username              string
	Password              string
	PrivateKey            string
	Host                  string
	Port                  string
	StrictHostKeyChecking bool
	UserKnownHostsFile    string
	MaxClients            int
	Timeout               time.Duration
	Dialer                Dialer

	mutexes [64]sync.Mutex
	clients [64]*ssh.Client
}

func (d *SSHDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	connect := func() (*ssh.Client, error) {
		config := &ssh.ClientConfig{
			User: d.Username,
			Auth: []ssh.AuthMethod{
				ssh.Password(d.Password),
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         d.Timeout,
		}
		if d.PrivateKey != "" {
			signer, err := ssh.ParsePrivateKey([]byte(d.PrivateKey))
			if err != nil {
				return nil, err
			}
			config.Auth = append([]ssh.AuthMethod{ssh.PublicKeys(signer)}, config.Auth...)
		}
		if d.StrictHostKeyChecking {
			file := d.UserKnownHostsFile
			if file == "" {
				file = os.ExpandEnv("$HOME/.ssh/known_hosts")
			}
			cb, err := knownhosts.New(file)
			if err != nil {
				return nil, err
			}
			config.HostKeyCallback = cb
		}
		dialer := d.Dialer
		if dialer == nil {
			dialer = &net.Dialer{Timeout: d.Timeout}
		}
		ctx, cancel := context.WithTimeout(ctx, config.Timeout)
		defer cancel()
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(d.Host, d.Port))
		if err != nil {
			return nil, err
		}
		c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
		if err != nil {
			return nil, err
		}
		return ssh.NewClient(c, chans, reqs), nil
	}

	maxClient := d.MaxClients
	if maxClient == 0 {
		maxClient = 1
	}

	n := 1
	if 0 < maxClient && maxClient < len(d.clients) {
		n = maxClient
	}
	n = int(fastrandn(uint32(n)))

	if d.clients[n] == nil {
		d.mutexes[n].Lock()
		c, err := connect()
		if err != nil {
			d.mutexes[n].Unlock()
			return nil, err
		}
		d.clients[n] = c
		d.mutexes[n].Unlock()
	}

	conn, err := d.clients[n].Dial(network, addr)
	if err != nil {
		time.Sleep(time.Duration(100+fastrandn(200)) * time.Millisecond)
		old := d.clients[n]
		d.mutexes[n].Lock()
		if d.clients[n] == old {
			d.clients[n], err = connect()
		}
		d.mutexes[n].Unlock()
		if c := d.clients[n]; c != nil && c != old {
			conn, err = c.Dial(network, addr)
		}
	}

	return conn, err
}
