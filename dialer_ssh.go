package main

import (
	"context"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

var _ Dialer = (*SSHDialer)(nil)

type SSHDialer struct {
	Username   string
	Password   string
	PrivateKey string
	Host       string
	Port       string
	Timeout    time.Duration
	Dialer     Dialer

	mu     sync.Mutex
	client *ssh.Client
}

func (d *SSHDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	dial := func() error {
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
				return err
			}
			config.Auth = append([]ssh.AuthMethod{ssh.PublicKeys(signer)}, config.Auth...)
		}
		dialer := d.Dialer
		if dialer == nil {
			dialer = &net.Dialer{Timeout: d.Timeout}
		}
		ctx, cancel := context.WithTimeout(ctx, config.Timeout)
		defer cancel()
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(d.Host, d.Port))
		if err != nil {
			return err
		}
		c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
		if err != nil {
			return err
		}
		d.client = ssh.NewClient(c, chans, reqs)
		return nil
	}

	if d.client == nil {
		d.mu.Lock()
		if d.client == nil {
			if err := dial(); err != nil {
				d.mu.Unlock()
				return nil, err
			}
		}
		d.mu.Unlock()
	}

	conn, err := d.client.Dial(network, addr)
	if err != nil {
		if terr, ok := err.(interface {
			Timeout() bool
		}); !(ok && terr.Timeout()) {
			time.Sleep(100 * time.Millisecond)
		}
		if err = dial(); err == nil {
			conn, err = d.client.Dial(network, addr)
		}
	}

	return conn, err
}
