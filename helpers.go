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
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unsafe"

	"github.com/nathanaelle/password/v2"
	"github.com/valyala/bytebufferpool"
	"golang.org/x/crypto/ocsp"
)

// fastrandn returns a pseudorandom uint32 in [0,n).
//
//go:noescape
//go:linkname fastrandn runtime.fastrandn
func fastrandn(x uint32) uint32

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

func btoi[B ~bool](x B) int {
	if x {
		return 1
	}
	return 0
}

func first[T, U any](t T, _ ...U) T {
	return t
}

func must[T, U any](t T, u ...U) T {
	v := any(u[len(u)-1])
	switch v := v.(type) {
	case bool:
		if !v {
			panic(v)
		}
	case error:
		if v != nil {
			panic(v)
		}
	}
	return t
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

func AppendLowerBytes(dst []byte, src []byte) []byte {
	for _, c := range src {
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst
}

// AppendSplitLines splits the input string by lines and appends them to the dst slice.
func AppendSplitLines(dst []string, input string) []string {
	var i int
	for {
		i = strings.IndexByte(input, '\n')
		if i > 0 {
			_ = input[i]
			if input[i-1] != '\r' {
				dst = append(dst, input[:i])
			} else {
				dst = append(dst, input[:i-1])
			}
			input = input[i+1:]
		} else if i == 0 {
			dst = append(dst, "")
			input = input[i+1:]
		} else {
			break
		}
	}

	if len(input) > 0 {
		if i = len(input) - 1; input[i] == '\r' {
			dst = append(dst, input[:i])
		} else {
			dst = append(dst, input)
		}
	}

	return dst
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
				dst = fmt.Append(dst, v)
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
	TLSConfig       *tls.Config
	MirrorHeader    bool
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

	c = tc

	if ln.MirrorHeader {
		c = &MirrorHeaderConn{Conn: c, Header: nil}
	}

	if ln.TLSConfig != nil {
		c = tls.Server(c, ln.TLSConfig)
	}

	return
}

type MirrorHeaderConn struct {
	net.Conn
	Header *bytebufferpool.ByteBuffer
}

func (c *MirrorHeaderConn) Read(b []byte) (n int, err error) {
	n, err = c.Conn.Read(b)
	if c.Header == nil {
		c.Header = bytebufferpool.Get()
		c.Header.Reset()
	}
	if err == nil && n > 0 && c.Header.Len() < 1500 {
		c.Header.Write(b[:n])
	}

	return
}

func GetMirrorHeader(conn net.Conn) *bytebufferpool.ByteBuffer {
	if c, ok := conn.(*tls.Conn); ok && c != nil {
		// conn = (*struct{ conn net.Conn })(unsafe.Pointer(c)).conn
		conn = c.NetConn()
	}
	if c, ok := conn.(*MirrorHeaderConn); ok && c.Header != nil && len(c.Header.B) > 0 {
		return c.Header
	}
	return nil
}

type MemoryListener struct {
	net.Listener

	once  sync.Once
	queue chan struct {
		conn net.Conn
		err  error
	}
}

func (ln *MemoryListener) init() {
	ln.queue = make(chan struct {
		conn net.Conn
		err  error
	}, 2048)
	go func() {
		for {
			c, err := ln.Listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					break
				}
				time.Sleep(10 * time.Millisecond)
				continue
			}
			ln.queue <- struct {
				conn net.Conn
				err  error
			}{c, err}
		}
	}()
}

func (ln *MemoryListener) Accept() (c net.Conn, err error) {
	ln.once.Do(ln.init)
	item := <-ln.queue
	c, err = item.conn, item.err
	return
}

func (ln *MemoryListener) Close() (err error) {
	err = ln.Listener.Close()
	for item := range ln.queue {
		if item.conn != nil {
			_ = item.conn.Close()
		}
	}
	return
}

func (ln *MemoryListener) Add(c net.Conn) {
	ln.once.Do(ln.init)
	ln.queue <- struct {
		conn net.Conn
		err  error
	}{c, nil}
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

// IPRange represents a range of IP addresses
type IPRange struct {
	StartInt uint32
	EndInt   uint32
	StartIP  netip.Addr
	EndIP    netip.Addr
	Length   int
}

// GetIPRange calculates the start IP, end IP, and number of IPs in a CIDR range
func GetIPRange(cidr string) (result IPRange, err error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return IPRange{}, err
	}

	startIP := prefix.Addr()
	startIPBytes := startIP.As4()
	startInt := uint32(startIPBytes[0])<<24 | uint32(startIPBytes[1])<<16 | uint32(startIPBytes[2])<<8 | uint32(startIPBytes[3])
	length := 1 << (32 - prefix.Bits()) // Number of IPs in the CIDR block

	// Calculate the end IP by adding the number of IPs in the range to the start IP
	endInt := startInt + uint32(length-1)
	endIP := netip.AddrFrom4([4]byte{
		byte(endInt >> 24),
		byte(endInt >> 16),
		byte(endInt >> 8),
		byte(endInt),
	})

	result = IPRange{
		StartInt: startInt,
		EndInt:   endInt,
		StartIP:  startIP,
		EndIP:    endIP,
		Length:   length,
	}

	return result, nil
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
	defer conn.Close()

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
	if ip == nil {
		return false
	}
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

func ReadFile(s string) (body []byte, err error) {
	var u *url.URL

	u, err = url.Parse(s)
	if err != nil {
		return
	}

	switch u.Scheme {
	case "":
		body, err = os.ReadFile(s)
	case "http", "https":
		var resp *http.Response
		resp, err = http.Get(s)
		if err == nil {
			defer resp.Body.Close()
			body, err = io.ReadAll(resp.Body)
		}
	default:
		err = errors.New("unsupported url: " + s)
	}

	return
}

func HtpasswdVerify(htpasswdFile string, req *http.Request) error {
	file, err := os.Open(htpasswdFile)
	if err != nil {
		return fmt.Errorf("open htpasswd file %s error: %w", htpasswdFile, err)
	}
	defer file.Close()

	s := req.Header.Get("authorization")
	if s == "" {
		return errors.New("no authorization header")
	}
	if !strings.HasPrefix(s, "Basic ") {
		return fmt.Errorf("unsupported authorization header: %+v", s)
	}
	data, err := base64.StdEncoding.DecodeString(s[6:])
	if err != nil {
		return fmt.Errorf("invalid authorization header: %+v", s)
	}
	parts := strings.SplitN(string(data), ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid authorization header: %+v", s)
	}
	user, pass := parts[0], parts[1]

	factory := &password.Factory{}
	factory.Register(password.MD5, password.SHA256, password.SHA512, password.BCRYPT)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, ':'); i > 0 && line[:i] == user {
			factory.Set(strings.TrimSpace(line[i+1:]))
			if factory.CrypterFound().Verify(s2b(pass)) {
				return nil
			}
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read htpasswd file %s error: %w", htpasswdFile, err)
	}

	return fmt.Errorf("wrong username or password: %+v", parts)
}

func GetOCSPStaple(ctx context.Context, transport http.RoundTripper, cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, errors.New("Nil x509 certificate")
	}

	if len(cert.OCSPServer) == 0 {
		return nil, errors.New("No OCSP server in certificate")
	}

	if len(cert.IssuingCertificateURL) == 0 {
		return nil, errors.New("no URL to issuing certificate")
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, cert.IssuingCertificateURL[0], nil)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("getting issuer certificate: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, fmt.Errorf("reading issuer certificate: %w", err)
	}

	issuer, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, fmt.Errorf("parsing issuer certificate: %w", err)
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

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if _, err := ocsp.ParseResponse(raw, issuer); err != nil {
		return nil, err
	}

	return raw, nil
}

// WildcardMatch from https://github.com/IGLOU-EU/go-wildcard
func WildcardMatch(pattern, s string) bool {
	if pattern == "" {
		return s == pattern
	}
	if pattern == "*" || s == pattern {
		return true
	}

	var lastErotemeByte byte
	var patternIndex, sIndex, lastStar, lastEroteme int
	patternLen := len(pattern)
	sLen := len(s)
	star := -1
	eroteme := -1

Loop:
	if sIndex >= sLen {
		goto checkPattern
	}

	if patternIndex >= patternLen {
		if star != -1 {
			patternIndex = star + 1
			lastStar++
			sIndex = lastStar
			goto Loop
		}
		return false
	}
	switch pattern[patternIndex] {
	case '.':
		// It matches any single character. So, we don't need to check anything.
	case '?':
		// '?' matches one character. Store its position and match exactly one character in the string.
		eroteme = patternIndex
		lastEroteme = sIndex
		lastErotemeByte = s[sIndex]
	case '*':
		// '*' matches zero or more characters. Store its position and increment the pattern index.
		star = patternIndex
		lastStar = sIndex
		patternIndex++
		goto Loop
	default:
		// If the characters don't match, check if there was a previous '?' or '*' to backtrack.
		if pattern[patternIndex] != s[sIndex] {
			if eroteme != -1 {
				patternIndex = eroteme + 1
				sIndex = lastEroteme
				eroteme = -1
				goto Loop
			}

			if star != -1 {
				patternIndex = star + 1
				lastStar++
				sIndex = lastStar
				goto Loop
			}

			return false
		}

		// If the characters match, check if it was not the same to validate the eroteme.
		if eroteme != -1 && lastErotemeByte != s[sIndex] {
			eroteme = -1
		}
	}

	patternIndex++
	sIndex++
	goto Loop

	// Check if the remaining pattern characters are '*' or '?', which can match the end of the string.
checkPattern:
	if patternIndex < patternLen {
		if pattern[patternIndex] == '*' {
			patternIndex++
			goto checkPattern
		} else if pattern[patternIndex] == '?' {
			if sIndex >= sLen {
				sIndex--
			}
			patternIndex++
			goto checkPattern
		}
	}

	return patternIndex == patternLen
}

type SlogWriter struct {
	Logger *slog.Logger
}

func (w SlogWriter) Write(b []byte) (int, error) {
	if w.Logger != nil {
		w.Logger.Info(b2s(b))
	}
	return len(b), nil
}

type FileLoader[T any] struct {
	Filename     string
	Unmarshal    func([]byte, any) error
	PollDuration time.Duration
	ErrorLogger  *log.Logger

	once  sync.Once
	mtime int64
	ptr   unsafe.Pointer
}

func (f *FileLoader[T]) load() {
	if f.Unmarshal == nil {
		if f.ErrorLogger != nil {
			f.ErrorLogger.Printf("FileLoader: empty unmarshal for %+v", f.Filename)
		}
		return
	}
	data, err := os.ReadFile(f.Filename)
	if err != nil {
		if f.ErrorLogger != nil {
			f.ErrorLogger.Printf("FileLoader: read file %+v error: %v", f.Filename, err)
		}
		return
	}
	v := new(T)
	err = f.Unmarshal(data, v)
	if err != nil {
		if f.ErrorLogger != nil {
			f.ErrorLogger.Printf("FileLoader: unmarshal data of %+v error: %v", f.Filename, err)
		}
		return
	}
	atomic.StorePointer(&f.ptr, (unsafe.Pointer)(v))
}

func (f *FileLoader[T]) Load() *T {
	f.once.Do(func() {
		f.load()
		go func() {
			dur := f.PollDuration
			if dur == 0 {
				dur = time.Minute
			}
			for range time.Tick(dur) {
				fi, err := os.Stat(f.Filename)
				if err != nil {
					if f.ErrorLogger != nil {
						f.ErrorLogger.Printf("FileLoader: stat %+v error: %v", f.Filename, err)
					}
					continue
				}
				mtime := fi.ModTime().Unix()
				if mtime != atomic.SwapInt64(&f.mtime, mtime) {
					f.load()
				}
			}
		}()
	})

	return (*T)(atomic.LoadPointer(&f.ptr))
}

type CachingMap[K comparable, V any] struct {
	// double buffering mechanism
	index int64
	maps  [2]map[K]V

	// write queue
	queue chan struct {
		key   K
		value V
	}

	getter   func(K) (V, error)
	maxsize  int
	duration time.Duration
}

func NewCachingMap[K comparable, V any](getter func(K) (V, error), maxsize int, duration time.Duration) *CachingMap[K, V] {
	cm := &CachingMap[K, V]{
		index: 0,
		maps: [2]map[K]V{
			make(map[K]V),
			make(map[K]V),
		},
		queue: make(chan struct {
			key   K
			value V
		}, 1024),
		getter:   getter,
		maxsize:  maxsize,
		duration: duration,
	}
	go func(cm *CachingMap[K, V]) {
		duration := cm.duration
		if duration == 0 {
			duration = time.Minute
		}
		ticker := time.NewTicker(duration)
		for {
			select {
			case kv := <-cm.queue:
				cm.maps[(atomic.LoadInt64(&cm.index)+1)%2][kv.key] = kv.value
			case <-ticker.C:
				atomic.StoreInt64(&cm.index, (atomic.LoadInt64(&cm.index)+1)%2)
				if m := cm.maps[(atomic.LoadInt64(&cm.index)+1)%2]; maxsize <= 0 || len(m) <= maxsize {
					for key, value := range cm.maps[atomic.LoadInt64(&cm.index)] {
						m[key] = value
					}
				} else {
					cm.maps[(atomic.LoadInt64(&cm.index)+1)%2] = make(map[K]V)
				}
			}
		}
	}(cm)
	return cm
}

func (cm *CachingMap[K, V]) Get(key K) (value V, ok bool, err error) {
	// fast path, lock-free
	value, ok = cm.maps[atomic.LoadInt64(&cm.index)][key]
	if ok {
		return
	}

	// slow path
	value, err = cm.getter(key)
	if err == nil {
		cm.queue <- struct {
			key   K
			value V
		}{key, value}
	}

	return
}

func AppendToLower(dst []byte, s string) []byte {
	n := len(s) - 1
	_ = s[n]
	for i := 0; i <= n; i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		dst = append(dst, c)
	}
	return dst
}
