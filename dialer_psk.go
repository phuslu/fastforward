package main

import (
	"context"
	"errors"
	"net"

	"github.com/phuslu/tlspsk"
)

type TLSPSKDialer struct {
	PSK      string
	Username string
	Password string
	Host     string
	Port     string
}

func (d *TLSPSKDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	config := &tlspsk.Config{
		CipherSuites: []uint16{tlspsk.TLS_PSK_WITH_AES_128_CBC_SHA},
		Certificates: []tlspsk.Certificate{tlspsk.Certificate{}},
		Extra: tlspsk.PSKConfig{
			GetIdentity: func() string { return "" },
			GetKey:      func(string) ([]byte, error) { return []byte(d.PSK), nil },
		},
	}

	conn, err := tlspsk.Dial("tcp", net.JoinHostPort(d.Host, d.Port), config)
	if err != nil {
		return nil, err
	}
	closeConn := &conn
	defer func() {
		if closeConn != nil {
			(*closeConn).Close()
		}
	}()

	buf := make([]byte, 0, len(network)+1+len(addr)+1+len(d.Username)+1+len(d.Password)+1+1)

	buf = append(buf, network...)
	buf = append(buf, '\n')
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
