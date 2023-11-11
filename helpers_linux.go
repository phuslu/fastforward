//go:build linux
// +build linux

package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
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
	BindInterface string
}

func (dc DailerController) Control(network, addr string, c syscall.RawConn) (err error) {
	return c.Control(func(fd uintptr) {
		if ip, err := netip.ParseAddr(dc.BindInterface); err == nil {
			var sa syscall.Sockaddr
			if ip.Is4() {
				ip4 := ip.As4()
				sa = &syscall.SockaddrInet4{
					Addr: [4]byte{ip4[0], ip4[1], ip4[2], ip4[3]},
				}
			} else {
				ip6 := ip.As16()
				sa = &syscall.SockaddrInet6{
					Addr: [16]byte{
						ip6[0], ip6[1], ip6[2], ip6[3],
						ip6[4], ip6[5], ip6[6], ip6[7],
						ip6[8], ip6[9], ip6[10], ip6[11],
						ip6[12], ip6[13], ip6[14], ip6[15],
					},
				}
			}
			const IP_BIND_ADDRESS_NO_PORT = 24
			err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, 1)
			if err != nil {
				return
			}
			err = syscall.Bind(int(fd), sa)
		} else if dc.BindInterface != "" {
			err = syscall.BindToDevice(int(fd), dc.BindInterface)
		}
	})
}

//go:linkname setsockopt syscall.setsockopt
func setsockopt(s int, level int, name int, val unsafe.Pointer, vallen uintptr) (err error)

func SetTcpBrutalRate(tc *net.TCPConn, rate uint64) (err error) {
	var c syscall.RawConn
	c, err = tc.SyscallConn()
	if err != nil {
		return
	}
	return c.Control(func(fd uintptr) {
		const TCP_BRUTAL_PARAMS = 23301
		err = syscall.SetsockoptString(int(fd), syscall.IPPROTO_TCP, syscall.TCP_CONGESTION, "brutal")
		if err != nil {
			err = os.NewSyscallError("setsockopt IPPROTO_TCP TCP_CONGESTION brutal", err)
		}
		params := struct {
			Rate     uint64
			CwndGain uint32
		}{
			Rate:     rate,
			CwndGain: 20, // hysteria2 default
		}
		err = setsockopt(int(fd), syscall.IPPROTO_TCP, TCP_BRUTAL_PARAMS, unsafe.Pointer(&params), unsafe.Sizeof(params))
		if err != nil {
			err = os.NewSyscallError("setsockopt IPPROTO_TCP TCP_BRUTAL_PARAMS", err)
		}
		return
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
