// Package testkit starts a throwaway lab for tests and benchmarks: an
// in-process sing-box server with one inbound per protocol, a target server
// answering 204, a trace endpoint, a download endpoint, a UDP DNS responder,
// a local TLS 1.3 site for Reality handshakes, and a TCP blackhole. Every
// credential is generated per lab and listens on loopback only.
package testkit

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/spec"

	"github.com/miekg/dns"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
)

const (
	SNI        = "lab.test"
	RealitySNI = "reality.test"
	WSPath     = "/vm"
)

// Protocols are the inbounds every lab runs, in test order.
var Protocols = []string{"shadowsocks", "vmess", "vless", "trojan", "hysteria2", "tuic"}

// LoopbackOnly is the allowlist a lab needs: its servers live on 127.0.0.1.
var LoopbackOnly = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}

// Lab is a running set of local servers.
type Lab struct {
	SSKey, SSKeyWrong     string
	UUID, UUIDWrong       string
	Password, PassWrong   string
	RealityPublic         string
	ShortID, ShortIDWrong string

	Ports      map[string]int // inbound port per protocol
	HTTPAddr   string         // target, trace and download server
	DNSAddr    string         // UDP DNS responder
	Blackhole  string         // accepts TCP and never answers
	DNSQueries atomic.Int64   `json:"-"`

	realityPrivate string
	certPEM        string
	keyPEM         string
	server         *box.Box
	closers        []func()
	mu             sync.Mutex
	held           []net.Conn
}

// Start brings up a lab. Close it when done.
func Start() (lab *Lab, err error) {
	l := &Lab{Ports: make(map[string]int)}
	defer func() {
		if err != nil {
			l.Close()
		}
	}()
	if err := l.generate(); err != nil {
		return nil, err
	}
	if err := l.startHTTP(); err != nil {
		return nil, err
	}
	if err := l.startDNS(); err != nil {
		return nil, err
	}
	if err := l.startBlackhole(); err != nil {
		return nil, err
	}
	realityPort, err := l.startRealitySite()
	if err != nil {
		return nil, err
	}
	if err := l.startServer(realityPort); err != nil {
		return nil, err
	}
	return l, nil
}

// Close stops every server of the lab.
func (l *Lab) Close() {
	if l.server != nil {
		l.server.Close()
	}
	for i := len(l.closers) - 1; i >= 0; i-- {
		l.closers[i]()
	}
	l.mu.Lock()
	for _, c := range l.held {
		c.Close()
	}
	l.mu.Unlock()
}

// Targets returns lab targets: one answering 204, one answering 200, and
// one that answers 200 where 204 is expected.
func (l *Lab) Targets() []spec.Target {
	base := "http://" + l.HTTPAddr
	return []spec.Target{
		{ID: "lab-204", URL: base + "/generate_204", Expect: 204},
		{ID: "lab-200", URL: base + "/ok", Expect: 200},
		{ID: "lab-wrong-status", URL: base + "/ok", Expect: 204},
	}
}

func (l *Lab) TraceURL() string    { return "http://" + l.HTTPAddr + "/cdn-cgi/trace" }
func (l *Lab) DownloadURL() string { return "http://" + l.HTTPAddr + "/__down?bytes=%d" }

// Outbound returns the client outbound for proto. variant "" is valid,
// "wrong" carries a wrong password or uuid, "wrong-short-id" a wrong
// Reality short id (vless only).
func (l *Lab) Outbound(proto, variant, tag string) map[string]any {
	ssKey, uuid, password, shortID := l.SSKey, l.UUID, l.Password, l.ShortID
	switch variant {
	case "wrong":
		ssKey, uuid, password = l.SSKeyWrong, l.UUIDWrong, l.PassWrong
	case "wrong-short-id":
		shortID = l.ShortIDWrong
	}
	m := map[string]any{"tag": tag, "server": "127.0.0.1", "server_port": l.Ports[proto]}
	insecure := func(alpn ...string) map[string]any {
		t := map[string]any{"enabled": true, "server_name": SNI, "insecure": true}
		if len(alpn) > 0 {
			t["alpn"] = alpn
		}
		return t
	}
	switch proto {
	case "shadowsocks":
		m["type"], m["method"], m["password"] = "shadowsocks", "2022-blake3-aes-128-gcm", ssKey
	case "vmess":
		m["type"], m["uuid"], m["alter_id"], m["security"] = "vmess", uuid, 0, "aes-128-gcm"
		m["transport"] = map[string]any{"type": "ws", "path": WSPath}
	case "vless":
		m["type"], m["uuid"], m["flow"] = "vless", uuid, "xtls-rprx-vision"
		m["tls"] = map[string]any{
			"enabled": true, "server_name": RealitySNI,
			"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
			"reality": map[string]any{"enabled": true, "public_key": l.RealityPublic, "short_id": shortID},
		}
	case "trojan":
		m["type"], m["password"], m["tls"] = "trojan", password, insecure()
	case "hysteria2":
		m["type"], m["password"], m["tls"] = "hysteria2", password, insecure("h3")
	case "tuic":
		m["type"], m["uuid"], m["password"] = "tuic", uuid, password
		m["congestion_control"], m["udp_relay_mode"], m["tls"] = "bbr", "native", insecure("h3")
	}
	return m
}

// OutboundJSON is Outbound encoded for a request.
func (l *Lab) OutboundJSON(proto, variant, tag string) json.RawMessage {
	b, _ := json.Marshal(l.Outbound(proto, variant, tag))
	return b
}

// Secrets lists every credential of the lab, for tests that grep logs.
func (l *Lab) Secrets() []string {
	return []string{l.SSKey, l.SSKeyWrong, l.UUID, l.UUIDWrong, l.Password, l.PassWrong, l.ShortID, l.ShortIDWrong, l.realityPrivate}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func newUUID() string {
	b := randBytes(16)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func (l *Lab) generate() error {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	l.SSKey = base64.StdEncoding.EncodeToString(randBytes(16))
	l.SSKeyWrong = base64.StdEncoding.EncodeToString(randBytes(16))
	l.UUID, l.UUIDWrong = newUUID(), newUUID()
	l.Password, l.PassWrong = hex.EncodeToString(randBytes(12)), hex.EncodeToString(randBytes(12))
	l.realityPrivate = base64.RawURLEncoding.EncodeToString(priv.Bytes())
	l.RealityPublic = base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	l.ShortID, l.ShortIDWrong = hex.EncodeToString(randBytes(8)), hex.EncodeToString(randBytes(8))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: SNI},
		DNSNames:     []string{SNI, RealitySNI},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	l.certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	l.keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}))
	return nil
}

func (l *Lab) startHTTP() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/generate_204", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.HandleFunc("/ok", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	mux.HandleFunc("/cdn-cgi/trace", func(w http.ResponseWriter, r *http.Request) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		fmt.Fprintf(w, "fl=lab\nh=%s\nip=%s\nts=%d\nloc=ZZ\ncolo=LAB\n", r.Host, host, time.Now().Unix())
	})
	mux.HandleFunc("/__down", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if err != nil || n < 0 || n > 100_000_000 {
			http.Error(w, "bad size", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		chunk := make([]byte, 64<<10)
		for n > 0 {
			k := min(int64(len(chunk)), n)
			if _, err := w.Write(chunk[:k]); err != nil {
				return
			}
			n -= k
		}
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	l.HTTPAddr = ln.Addr().String()
	l.closers = append(l.closers, func() { srv.Close() })
	return nil
}

func (l *Lab) startDNS() error {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var q dns.Msg
			if q.Unpack(buf[:n]) != nil || len(q.Question) == 0 {
				continue
			}
			l.DNSQueries.Add(1)
			var a dns.Msg
			a.SetReply(&q)
			rr, _ := dns.NewRR(q.Question[0].Name + " 60 IN A 192.0.2.53")
			a.Answer = append(a.Answer, rr)
			if out, err := a.Pack(); err == nil {
				_, _ = pc.WriteTo(out, addr)
			}
		}
	}()
	l.DNSAddr = pc.LocalAddr().String()
	l.closers = append(l.closers, func() { pc.Close() })
	return nil
}

func (l *Lab) startBlackhole() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			l.mu.Lock()
			l.held = append(l.held, c)
			l.mu.Unlock()
			go func() {
				_, _ = io.Copy(io.Discard, c)
				c.Close()
			}()
		}
	}()
	l.Blackhole = ln.Addr().String()
	l.closers = append(l.closers, func() { ln.Close() })
	return nil
}

func (l *Lab) startRealitySite() (int, error) {
	cert, err := tls.X509KeyPair([]byte(l.certPEM), []byte(l.keyPEM))
	if err != nil {
		return 0, err
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13})
	if err != nil {
		return 0, err
	}
	srv := &http.Server{
		Handler:           http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") }),
		ReadHeaderTimeout: 5 * time.Second,
		// Reality clients close the fallback handshake early by design.
		ErrorLog: log.New(io.Discard, "", 0),
	}
	srv.SetKeepAlivesEnabled(false)
	go func() { _ = srv.Serve(ln) }()
	l.closers = append(l.closers, func() { srv.Close() })
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func freePort(network string) (int, error) {
	if network == "udp" {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return 0, err
		}
		defer pc.Close()
		return pc.LocalAddr().(*net.UDPAddr).Port, nil
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

func (l *Lab) startServer(realityPort int) error {
	for _, p := range Protocols {
		network := "tcp"
		if p == "hysteria2" || p == "tuic" {
			network = "udp"
		}
		port, err := freePort(network)
		if err != nil {
			return err
		}
		l.Ports[p] = port
	}
	tlsIn := func(alpn ...string) map[string]any {
		m := map[string]any{"enabled": true, "server_name": SNI, "certificate": []string{l.certPEM}, "key": []string{l.keyPEM}}
		if len(alpn) > 0 {
			m["alpn"] = alpn
		}
		return m
	}
	inbound := func(proto string, fields map[string]any) map[string]any {
		fields["type"], fields["tag"], fields["listen"], fields["listen_port"] = proto, proto, "127.0.0.1", l.Ports[proto]
		return fields
	}
	config := map[string]any{
		"log": map[string]any{"disabled": true},
		"inbounds": []any{
			inbound("shadowsocks", map[string]any{"method": "2022-blake3-aes-128-gcm", "password": l.SSKey}),
			inbound("vmess", map[string]any{
				"users":     []any{map[string]any{"uuid": l.UUID, "alterId": 0}},
				"transport": map[string]any{"type": "ws", "path": WSPath},
			}),
			inbound("vless", map[string]any{
				"users": []any{map[string]any{"uuid": l.UUID, "flow": "xtls-rprx-vision"}},
				"tls": map[string]any{
					"enabled": true, "server_name": RealitySNI,
					"reality": map[string]any{
						"enabled":     true,
						"handshake":   map[string]any{"server": "127.0.0.1", "server_port": realityPort},
						"private_key": l.realityPrivate,
						"short_id":    []string{l.ShortID},
					},
				},
			}),
			inbound("trojan", map[string]any{"users": []any{map[string]any{"password": l.Password}}, "tls": tlsIn()}),
			inbound("hysteria2", map[string]any{"users": []any{map[string]any{"password": l.Password}}, "tls": tlsIn("h3")}),
			inbound("tuic", map[string]any{
				"users":              []any{map[string]any{"uuid": l.UUID, "password": l.Password}},
				"congestion_control": "bbr", "tls": tlsIn("h3"),
			}),
		},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	}
	raw, err := json.Marshal(config)
	if err != nil {
		return err
	}
	ctx := include.Context(context.Background())
	opts, err := sjson.UnmarshalExtendedContext[option.Options](ctx, raw)
	if err != nil {
		return fmt.Errorf("decode lab server config: %w", err)
	}
	inst, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		return fmt.Errorf("create lab server: %w", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return fmt.Errorf("start lab server: %w", err)
	}
	l.server = inst
	return nil
}

// FDs counts the process's open file descriptors, or -1 where the count is
// not available.
func FDs() int {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		if n, err := countDir(dir); err == nil {
			return n
		}
	}
	return -1
}

func countDir(dir string) (int, error) {
	f, err := os.Open(dir)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	names, err := f.Readdirnames(-1)
	if err != nil {
		return 0, err
	}
	// The directory handle opened here is itself one of the entries.
	return len(names) - 1, nil
}
