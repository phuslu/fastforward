package main

import (
	"context"
	"crypto/tls"
	"errors"
	"net"

	quic "github.com/lucas-clemente/quic-go"
)

type QuicDialer struct {
	PSK      string
	Username string
	Password string
	Host     string
	Port     string
}

func (d *QuicDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	session, err := quic.DialAddr(addr, tlsConfig, nil)
	if err != nil {
		return nil, err
	}

	sendStream, err := session.OpenStream()
	if err != nil {
		return nil, err
	}

	conn := &quicConn{
		session:    session,
		sendStream: sendStream,
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
