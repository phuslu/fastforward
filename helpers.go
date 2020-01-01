package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unsafe"

	"github.com/google/shlex"
	"golang.org/x/crypto/ocsp"
	"golang.org/x/time/rate"
)

func b2s(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func s2b(s string) (b []byte) {
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&b))
	sh := *(*reflect.StringHeader)(unsafe.Pointer(&s))
	bh.Data = sh.Data
	bh.Len = sh.Len
	bh.Cap = sh.Len
	return b
}

type IPInt uint32

func NewIPInt(ip string) IPInt {
	var dots int
	var i, j IPInt
	for k := range ip {
		switch ip[k] {
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			j = j*10 + IPInt(ip[k]-'0')
		case '.':
			if j >= 256 {
				return 0
			}
			i = i*256 + j
			j = 0
			dots++
		default:
			return 0
		}
	}
	if dots != 3 || j >= 256 {
		return 0
	}
	return i*256 + j
}

type ByteSliceWriter struct {
	b []byte
}

func (w *ByteSliceWriter) Write(p []byte) (int, error) {
	w.b = append(w.b, p...)
	return len(p), nil
}

func AppendLowerBytes(dst []byte, src []byte) []byte {
	for _, c := range src {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst
}

func AppendSprintf(dst []byte, format string, a ...interface{}) []byte {
	w := &ByteSliceWriter{dst}
	fmt.Fprintf(w, format, a...)
	return w.b
}

func AppendTemplate(dst []byte, template string, startTag, endTag byte, m map[string]interface{}, stripSpace bool) []byte {
	j := 0
	for i := 0; i < len(template); i++ {
		switch template[i] {
		case startTag:
			dst = append(dst, template[j:i]...)
			j = i
		case endTag:
			v, ok := m[template[j+1:i]]
			if !ok {
				dst = append(dst, template[j:i]...)
				j = i
				continue
			}
			switch v.(type) {
			case string:
				dst = append(dst, v.(string)...)
			case []byte:
				dst = append(dst, v.([]byte)...)
			case int:
				dst = strconv.AppendInt(dst, int64(v.(int)), 10)
			case int8:
				dst = strconv.AppendInt(dst, int64(v.(int8)), 10)
			case int16:
				dst = strconv.AppendInt(dst, int64(v.(int16)), 10)
			case int32:
				dst = strconv.AppendInt(dst, int64(v.(int32)), 10)
			case int64:
				dst = strconv.AppendInt(dst, v.(int64), 10)
			case uint:
				dst = strconv.AppendUint(dst, uint64(v.(uint)), 10)
			case uint8:
				dst = strconv.AppendUint(dst, uint64(v.(uint8)), 10)
			case uint16:
				dst = strconv.AppendUint(dst, uint64(v.(uint16)), 10)
			case uint32:
				dst = strconv.AppendUint(dst, uint64(v.(uint32)), 10)
			case uint64:
				dst = strconv.AppendUint(dst, v.(uint64), 10)
			case float32:
				dst = strconv.AppendFloat(dst, float64(v.(float32)), 'f', -1, 64)
			case float64:
				dst = strconv.AppendFloat(dst, v.(float64), 'f', -1, 64)
			default:
				dst = append(dst, fmt.Sprint(v)...)
			}
			j = i + 1
		case '\r', '\n':
			if stripSpace {
				dst = append(dst, template[j:i]...)
				for j = i; j < len(template); j++ {
					b := template[j]
					if b != ' ' && b != '\t' && b != '\r' && b != '\n' {
						break
					}
				}
				i = j
			}
		}
	}
	dst = append(dst, template[j:]...)
	return dst
}

func AESCBCBase64Decrypt(text string, ekey []byte, ikey []byte) ([]byte, error) {
	if n := len(text) % 4; n > 0 {
		text += string([]byte{'=', '=', '='}[:4-n])
	}

	ciphertext, err := base64.URLEncoding.DecodeString(text)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("crypto/cipher: input not full blocks")
	}

	block, err := aes.NewCipher(ekey)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))
	copy(plaintext, ciphertext)

	mode := cipher.NewCBCDecrypter(block, ikey)
	mode.CryptBlocks(plaintext, plaintext)

	plaintext = bytes.TrimRightFunc(plaintext, func(r rune) bool { return !unicode.IsPrint(r) })

	return plaintext, nil
}

func AppendAESCBCBase64Encryption(dst []byte, text []byte, key, iv []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil
	}

	n := len(text)
	if i := n % aes.BlockSize; i != 0 {
		n += aes.BlockSize - i
	}

	ciphertext := make([]byte, n)
	copy(ciphertext, text)

	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, ciphertext)

	old := len(dst)
	need := base64.URLEncoding.EncodedLen(len(ciphertext))
	for cap(dst)-len(dst) < need {
		dst = append(dst[:cap(dst)], 0)
	}
	base64.URLEncoding.Encode(dst[old:], ciphertext)

	if dst[old+need-1] == '=' {
		need--
	}
	if dst[old+need-1] == '=' {
		need--
	}

	return dst[:old+need]
}

type FlushWriter struct {
	w io.Writer
}

func (fw FlushWriter) Write(p []byte) (n int, err error) {
	n, err = fw.w.Write(p)
	if f, ok := fw.w.(http.Flusher); ok {
		f.Flush()
	}
	return
}

type TCPListener struct {
	*net.TCPListener
	KeepAlivePeriod time.Duration
	ReadBufferSize  int
	WriteBufferSize int
}

func (ln TCPListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	if ln.KeepAlivePeriod > 0 {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(ln.KeepAlivePeriod)
	}
	if ln.ReadBufferSize > 0 {
		tc.SetReadBuffer(ln.ReadBufferSize)
	}
	if ln.WriteBufferSize > 0 {
		tc.SetWriteBuffer(ln.WriteBufferSize)
	}
	return tc, nil
}

type ConnWithData struct {
	net.Conn
	Data []byte
}

func (c *ConnWithData) Read(b []byte) (int, error) {
	if c.Data == nil {
		return c.Conn.Read(b)
	}

	n := copy(b, c.Data)
	if n < len(c.Data) {
		c.Data = c.Data[n:]
	} else {
		c.Data = nil
	}

	return n, nil
}

type ConnWithBuffers struct {
	net.Conn
	Buffers net.Buffers
}

func (c *ConnWithBuffers) Read(b []byte) (int, error) {
	if c.Buffers == nil {
		return c.Conn.Read(b)
	}

	var total int
	for {
		n := copy(b, c.Buffers[0])
		total += n

		if n < len(c.Buffers[0]) {
			// b is full
			c.Buffers[0] = c.Buffers[0][n:]
			break
		}

		c.Buffers = c.Buffers[1:]
		if len(c.Buffers) == 0 {
			c.Buffers = nil
			break
		}

		b = b[n:]
		if len(b) == 0 {
			break
		}
	}

	return total, nil
}

// https://github.com/hankjacobs/cidr
func GetIPRange(cidr string) (from, to net.IP, err error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, nil, err
	}

	from = ip.Mask(ipNet.Mask)
	ones, total := ipNet.Mask.Size()
	zeros := total - ones
	count := (1 << uint32(zeros)) // 2 ^ zeros

	to = make(net.IP, len(from))
	copy(to, from)

	i := len(to) - 1
	for i >= 0 {
		if count%256 == 0 {
			to[i] = 255
			count /= 256
		} else {
			to[i] += byte(count - 1)
			break
		}
		i--
	}

	return
}

func MergeCIDRToIPList(r io.Reader) ([]IPInt, error) {
	scanner := bufio.NewScanner(r)

	ips := make([]IPInt, 0)

	for scanner.Scan() {
		cidr := strings.TrimSpace(scanner.Text())

		from, to, err := GetIPRange(cidr)
		if err != nil {
			continue
		}

		a, b := NewIPInt(from.String()), NewIPInt(to.String())

		if len(ips) > 0 && ips[len(ips)-1] == a-1 {
			ips[len(ips)-1] = b
		} else {
			ips = append(ips, a, b)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return ips, nil
}

func LookupEcdsaCiphers(clientHello *tls.ClientHelloInfo) (bool, uint16) {
	for _, cipher := range clientHello.CipherSuites {
		switch cipher {
		case tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256:
			return true, cipher
		case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
			return false, cipher
		case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA:
			return false, 0
		}
	}
	return false, 0
}

func IsTLSGreaseCode(c uint16) bool {
	return c&0x0f0f == 0x0a0a && c&0xff == c>>8
}

func GetPreferedLocalIP() (net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return nil, err
	}

	s, _, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return nil, err
	}

	return net.ParseIP(s), nil
}

func IsTimeout(err error) bool {
	switch err {
	case nil:
		return false
	case context.Canceled:
		return true
	}

	if terr, ok := err.(interface {
		Timeout() bool
	}); ok {
		return terr.Timeout()
	}

	return false
}

// see https://en.wikipedia.org/wiki/Reserved_IP_addresses
func IsReservedIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		switch ip4[0] {
		case 10:
			return true
		case 100:
			return ip4[1] >= 64 && ip4[1] <= 127
		case 127:
			return true
		case 169:
			return ip4[1] == 254
		case 172:
			return ip4[1] >= 16 && ip4[1] <= 31
		case 192:
			switch ip4[1] {
			case 0:
				switch ip4[2] {
				case 0, 2:
					return true
				}
			case 18, 19:
				return true
			case 51:
				return ip4[2] == 100
			case 88:
				return ip4[2] == 99
			case 168:
				return true
			}
		case 203:
			return ip4[1] == 0 && ip4[2] == 113
		case 224:
			return true
		case 240:
			return true
		}
	}
	return false
}

type LimiterReader struct {
	r       io.Reader
	limiter *rate.Limiter
}

func (r *LimiterReader) Read(buf []byte) (int, error) {
	n, err := r.r.Read(buf)
	if n <= 0 {
		return n, err
	}
	if r.limiter != nil {
		r.limiter.Wait(context.Background())
	}
	return n, err
}

func NewLimiterReader(r io.Reader, limit int64) io.Reader {
	if limit > 0 {
		return &LimiterReader{
			r:       r,
			limiter: rate.NewLimiter(rate.Limit(limit), int(limit/10)),
		}
	}
	return r
}

func ReadFile(s string) (body []byte, err error) {
	var u *url.URL

	u, err = url.Parse(s)
	if err != nil {
		return
	}

	switch u.Scheme {
	case "":
		body, err = ioutil.ReadFile(s)
	case "http", "https":
		var resp *http.Response
		resp, err = http.Get(s)
		if err == nil {
			defer resp.Body.Close()
			body, err = ioutil.ReadAll(resp.Body)
		}
	default:
		err = errors.New("unsupported url: " + s)
	}

	return
}

func SplitCommandLine(command string) (string, []string, error) {
	parts, err := shlex.Split(command)
	if err != nil {
		return "", nil, err
	}

	command = parts[0]

	if strings.HasPrefix(command, "./") {
		exe, err := os.Executable()
		if err != nil {
			return "", nil, err
		}

		command = filepath.Join(filepath.Dir(exe), command[2:])
	}

	if !strings.Contains(command, "/") {
		cmd, err := exec.LookPath(command)
		if err != nil {
			return "", nil, err
		}

		command = cmd
	}

	return command, parts[1:], nil
}

func StartSupervisor() {
	switch os.Getenv("supervisor") {
	case "1":
		break
	case "0":
		executable, _ := os.Executable()
		SetProcessName(filepath.Base(executable) + ": worker process " + executable)
		return
	case "":
		return
	}

	executable, _ := os.Executable()
	os.Chdir(filepath.Dir(executable))

	// deep copy os.Args & os.Environ
	osArgs := strings.Split(strings.Join(os.Args, "\x00"), "\x00")
	osEnviron := strings.Split(strings.Replace(strings.Join(os.Environ(), "\x00"), "supervisor=1", "supervisor=0", -1), "\x00")

	var child *os.Process
	var supervisor func()
	supervisor = func() {
		p, err := os.StartProcess(executable, osArgs, &os.ProcAttr{
			Dir:   ".",
			Env:   osEnviron,
			Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
		})
		if err != nil {
			panic("os.StartProcess error: " + err.Error())
		}

		if child != nil {
			child.Signal(syscall.SIGHUP)
		}

		child = p

		SetProcessName(filepath.Base(executable) + ": master process " + executable)

		ps, err := p.Wait()
		if ps != nil && !ps.Success() {
			go supervisor()
		}

		return
	}

	go supervisor()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)
	signal.Notify(c, syscall.SIGTERM)

	for {
		switch sig := <-c; sig {
		case syscall.SIGHUP:
			go supervisor()
		case syscall.SIGTERM:
			child.Signal(sig)
			os.Exit(0)
		}
	}
}

func GetOCSPStaple(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, errors.New("Nil x509 certificate")
	}

	if len(cert.OCSPServer) == 0 {
		return nil, errors.New("No OCSP server in certificate")
	}

	if len(cert.IssuingCertificateURL) == 0 {
		return nil, errors.New("no URL to issuing certificate")
	}

	resp, err := http.Get(cert.IssuingCertificateURL[0])
	if err != nil {
		return nil, fmt.Errorf("getting issuer certificate: %v", err)
	}
	defer resp.Body.Close()

	b, err := ioutil.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading issuer certificate: %v", err)
	}

	issuer, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, fmt.Errorf("parsing issuer certificate: %v", err)
	}

	b, err = ocsp.CreateRequest(cert, issuer, nil)
	if err != nil {
		return nil, err
	}
	r := bytes.NewReader(b)

	resp, err = http.Post(cert.OCSPServer[0], "text/ocsp", r)
	if resp != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if _, err := ocsp.ParseResponse(raw, issuer); err != nil {
		return nil, err
	}

	return raw, nil
}
