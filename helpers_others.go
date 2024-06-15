//go:build !linux
// +build !linux

package main

import (
	"context"
	"errors"
	"net"
	"syscall"
)

type ListenConfig struct {
	ReusePort   bool
	FastOpen    bool
	DeferAccept bool
}

func (ln ListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

func (ln ListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	laddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}

	return net.ListenUDP(network, laddr)
}

type DailerController struct {
	Interface string
}

func (dc DailerController) Control(network, address string, c syscall.RawConn) error {
	return nil
}

func SetTcpBrutalRate(tc *net.TCPConn, rate uint64) error {
	return nil
}

func SetProcessName(name string) error {
	return nil
}

func ReadHTTPHeader(conn *net.TCPConn) ([]byte, *net.TCPConn, error) {
	return nil, conn, errors.New("not implemented")
}
