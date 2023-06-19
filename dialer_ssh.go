package main

import (
	"context"
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

var _ Dialer = (*SSHDialer)(nil)

type SSHDialer struct {
	Username   string
	Password   string
	PrivateKey string
	Host       string
	Port       string
	Dialer     Dialer

	mu     sync.Mutex
	client *ssh.Client
}

func (d *SSHDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if d.client == nil {
		d.mu.Lock()
		if d.client == nil {
			config := &ssh.ClientConfig{
				User: d.Username,
				Auth: []ssh.AuthMethod{
					ssh.Password(d.Password),
				},
			}
			if d.PrivateKey != "" {
				signer, err := ssh.ParsePrivateKey([]byte(d.PrivateKey))
				if err != nil {
					d.mu.Unlock()
					return nil, err
				}
				config.Auth = append([]ssh.AuthMethod{ssh.PublicKeys(signer)}, config.Auth...)
			}
			dial := (&net.Dialer{}).DialContext
			if d.Dialer != nil {
				dial = d.Dialer.DialContext
			}
			conn, err := dial(ctx, network, addr)
			if err != nil {
				d.mu.Unlock()
				return nil, err
			}
			c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
			if err != nil {
				d.mu.Unlock()
				return nil, err
			}
			d.client = ssh.NewClient(c, chans, reqs)
		}
		d.mu.Unlock()
	}

	return d.client.Dial(network, addr)
}
