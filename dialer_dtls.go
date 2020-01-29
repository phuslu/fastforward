package main

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/pion/dtls"
)

type DTLSDialer struct {
	PSK      string
	Username string
	Password string
	Host     string
	Port     string
}

func (d *DTLSDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp6", "tcp4":
	default:
		return nil, errors.New("proxy: no support for DTLS proxy connections of type " + network)
	}

	raddr, err := net.ResolveUDPAddr(network, net.JoinHostPort(d.Host, d.Port))
	if err != nil {
		return nil, err
	}

	config := &dtls.Config{
		PSK: func(hint []byte) ([]byte, error) {
			println("Server's hint:", hint)
			return []byte{0xAB, 0xC1, 0x23}, nil
		},
		PSKIdentityHint:      []byte("Pion DTLS Server"),
		CipherSuites:         []dtls.CipherSuiteID{dtls.TLS_PSK_WITH_AES_128_CCM_8},
		ExtendedMasterSecret: dtls.RequireExtendedMasterSecret,
		ConnectTimeout:       dtls.ConnectTimeoutOption(30 * time.Second),
	}

	conn, err := dtls.Dial(network, raddr, config)
	if err != nil {
		return nil, err
	}
	closeConn := &conn
	defer func() {
		if closeConn != nil {
			(*closeConn).Close()
		}
	}()

	// the size here is just an estimate
	buf := make([]byte, 0, len(addr)+1+len(d.Username)+1+len(d.Password)+1+1)

	buf = append(buf, addr...)
	buf = append(buf, '\n')
	buf = append(buf, d.Username...)
	buf = append(buf, ':')
	buf = append(buf, d.Password...)
	buf = append(buf, '\n', '\n')

	if _, err := conn.Write(buf); err != nil {
		return nil, errors.New("proxy: failed to write greeting to DTLS proxy at " + d.Host + ": " + err.Error())
	}

	closeConn = nil
	return conn, nil
}
