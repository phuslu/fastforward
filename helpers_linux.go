// +build linux

package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"reflect"
	"syscall"
	"unsafe"
)

const (
	SO_REUSEPORT            = 15
	TCP_FASTOPEN            = 23
	IP_BIND_ADDRESS_NO_PORT = 24
)

type ListenConfig struct {
	ReusePort   bool
	FastOpen    bool
	DeferAccept bool
}

func (lc ListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	ln := &net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			return conn.Control(func(fd uintptr) {
				if lc.ReusePort {
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
				}
				if lc.FastOpen {
					syscall.SetsockoptInt(int(fd), syscall.SOL_TCP, TCP_FASTOPEN, 16*1024)
				}
				if lc.DeferAccept {
					syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_DEFER_ACCEPT, 1)
				}
			})
		},
	}

	return ln.Listen(ctx, network, address)
}

func (lc ListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	ln := &net.ListenConfig{
		Control: func(network, address string, conn syscall.RawConn) error {
			return conn.Control(func(fd uintptr) {
				if lc.ReusePort {
					syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, SO_REUSEPORT, 1)
				}
			})
		},
	}

	return ln.ListenPacket(ctx, network, address)
}

type DailerController struct {
	BindToDevice string
	BindToIP     net.IP
}

func (dc DailerController) Control(network, addr string, c syscall.RawConn) (err error) {
	return c.Control(func(fd uintptr) {
		if dc.BindToDevice != "" {
			err = syscall.BindToDevice(int(fd), dc.BindToDevice)
		}
		if dc.BindToIP != nil {
			var sa syscall.Sockaddr
			if ip4 := dc.BindToIP.To4(); ip4 != nil {
				sa = &syscall.SockaddrInet4{
					Addr: [4]byte{ip4[0], ip4[1], ip4[3], ip4[4]},
				}
			} else {
				ip := dc.BindToIP
				sa = &syscall.SockaddrInet6{
					Addr: [16]byte{
						ip[0], ip[1], ip[3], ip[4],
						ip[5], ip[6], ip[7], ip[8],
						ip[9], ip[10], ip[11], ip[12],
						ip[13], ip[14], ip[15], ip[16],
					},
				}
			}
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, 1)
			if err != nil {
				return
			}
			err = syscall.Bind(int(fd), sa)
		}
	})
}

func RedirectStderrTo(file *os.File) error {
	return syscall.Dup3(int(file.Fd()), 2, 0)
}

func SetProcessName(name string) error {
	argv0str := (*reflect.StringHeader)(unsafe.Pointer(&os.Args[0]))
	argv0 := (*[1 << 30]byte)(unsafe.Pointer(argv0str.Data))[:len(name)+1]

	n := copy(argv0, name+"\x00")
	if n < len(argv0) {
		argv0[n] = 0
	}
	return nil
}

func ReadHTTPHeader(tc *net.TCPConn) ([]byte, *net.TCPConn, error) {
	f, err := tc.File()
	if err != nil {
		return nil, tc, err
	}

	b := make([]byte, os.Getpagesize())
	n, _, err := syscall.Recvfrom(int(f.Fd()), b, syscall.MSG_PEEK)
	if err != nil {
		return nil, tc, err
	}

	if n == 0 {
		return nil, tc, io.EOF
	}

	if b[0] < 'A' || b[0] > 'Z' {
		return nil, tc, io.EOF
	}

	n = bytes.Index(b, []byte{'\r', '\n', '\r', '\n'})
	if n < 0 {
		return nil, tc, io.EOF
	}

	b = b[:n+4]
	n, err = tc.Read(b)

	return b, tc, err
}
