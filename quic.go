package main

import (
	"context"
	"net"
	"time"

	quic "github.com/lucas-clemente/quic-go"
)

type quicConn struct {
	session quic.Session

	receiveStream quic.Stream
	sendStream    quic.Stream
}

func (c *quicConn) Read(b []byte) (int, error) {
	if c.receiveStream == nil {
		var err error
		c.receiveStream, err = c.session.AcceptStream(context.Background())
		// TODO: check stream id
		if err != nil {
			return 0, err
		}
		// quic.Stream.Close() closes the stream for writing
		err = c.receiveStream.Close()
		if err != nil {
			return 0, err
		}
	}

	return c.receiveStream.Read(b)
}

func (c *quicConn) Write(b []byte) (int, error) {
	return c.sendStream.Write(b)
}

// LocalAddr returns the local network address.
// needed to fulfill the net.Conn interface
func (c *quicConn) LocalAddr() net.Addr {
	return c.session.LocalAddr()
}

// RemoteAddr returns the remote network address.
func (c *quicConn) RemoteAddr() net.Addr {
	return c.session.RemoteAddr()
}

func (c *quicConn) Close() error {
	return c.session.Close()
}

func (c *quicConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *quicConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *quicConn) SetWriteDeadline(t time.Time) error {
	return nil
}

var _ net.Conn = &quicConn{}
