// aux generates throwaway parameters and the upstream sing-box server
// config (setup), and serves the 204 target plus a local TLS 1.3 site used
// as the reality handshake destination (serve).
package main

import (
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
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"benchharness"
)

func randB(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func uuid() string {
	b := randB(16)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func must(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func setup(dir string) {
	must(os.MkdirAll(dir, 0o755))
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	must(err)
	p := harness.Params{
		Host: "127.0.0.1",
		Ports: map[string]int{
			"ss": 20001, "vmess_ws": 20002, "vless_reality": 20003, "trojan_tls": 20004,
			"hysteria2": 20005, "tuic": 20006, "vless_reality_public": 20013,
		},
		SSKey:          base64.StdEncoding.EncodeToString(randB(16)),
		SSKeyWrong:     base64.StdEncoding.EncodeToString(randB(16)),
		UUID:           uuid(),
		UUIDWrong:      uuid(),
		Password:       hex.EncodeToString(randB(12)),
		PasswordWrong:  hex.EncodeToString(randB(12)),
		RealityPriv:    base64.RawURLEncoding.EncodeToString(priv.Bytes()),
		RealityPub:     base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()),
		ShortID:        hex.EncodeToString(randB(8)),
		ShortIDWrong:   hex.EncodeToString(randB(8)),
		RealitySNI:     "reality.test",
		RealityPubSNI:  "www.apple.com",
		TLSSNI:         "bench.test",
		WSPath:         "/vm",
		TargetURL:      "http://127.0.0.1:18204/generate_204",
		TargetAddr:     "127.0.0.1:18204",
		RealityDest:    "127.0.0.1:18443",
		RealityPubDest: "www.apple.com:443",
	}

	// self-signed ECDSA cert for trojan, hysteria2, tuic and the local reality dest
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "bench.test"},
		DNSNames:     []string{"bench.test", "reality.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	must(err)
	kder, err := x509.MarshalECPrivateKey(key)
	must(err)
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	must(os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644))
	must(os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600))

	tlsIn := func(alpn ...string) map[string]any {
		m := map[string]any{"enabled": true, "server_name": p.TLSSNI, "certificate_path": certPath, "key_path": keyPath}
		if len(alpn) > 0 {
			m["alpn"] = alpn
		}
		return m
	}
	reality := func(sni, host string, port int) map[string]any {
		return map[string]any{
			"enabled": true, "server_name": sni,
			"reality": map[string]any{
				"enabled":     true,
				"handshake":   map[string]any{"server": host, "server_port": port},
				"private_key": p.RealityPriv,
				"short_id":    []string{p.ShortID},
			},
		}
	}
	srv := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"inbounds": []any{
			map[string]any{"type": "shadowsocks", "tag": "ss", "listen": "127.0.0.1", "listen_port": p.Ports["ss"],
				"method": "2022-blake3-aes-128-gcm", "password": p.SSKey},
			map[string]any{"type": "vmess", "tag": "vmess", "listen": "127.0.0.1", "listen_port": p.Ports["vmess_ws"],
				"users":     []any{map[string]any{"uuid": p.UUID, "alterId": 0}},
				"transport": map[string]any{"type": "ws", "path": p.WSPath}},
			map[string]any{"type": "vless", "tag": "vless", "listen": "127.0.0.1", "listen_port": p.Ports["vless_reality"],
				"users": []any{map[string]any{"uuid": p.UUID, "flow": "xtls-rprx-vision"}},
				"tls":   reality(p.RealitySNI, "127.0.0.1", 18443)},
			map[string]any{"type": "vless", "tag": "vless-public", "listen": "127.0.0.1", "listen_port": p.Ports["vless_reality_public"],
				"users": []any{map[string]any{"uuid": p.UUID, "flow": "xtls-rprx-vision"}},
				"tls":   reality(p.RealityPubSNI, "www.apple.com", 443)},
			map[string]any{"type": "trojan", "tag": "trojan", "listen": "127.0.0.1", "listen_port": p.Ports["trojan_tls"],
				"users": []any{map[string]any{"password": p.Password}}, "tls": tlsIn()},
			map[string]any{"type": "hysteria2", "tag": "hy2", "listen": "127.0.0.1", "listen_port": p.Ports["hysteria2"],
				"users": []any{map[string]any{"password": p.Password}}, "tls": tlsIn("h3")},
			map[string]any{"type": "tuic", "tag": "tuic", "listen": "127.0.0.1", "listen_port": p.Ports["tuic"],
				"users":              []any{map[string]any{"uuid": p.UUID, "password": p.Password}},
				"congestion_control": "bbr", "tls": tlsIn("h3")},
		},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
	}
	pb, _ := json.MarshalIndent(p, "", "  ")
	sb, _ := json.MarshalIndent(srv, "", "  ")
	must(os.WriteFile(filepath.Join(dir, "params.json"), pb, 0o644))
	must(os.WriteFile(filepath.Join(dir, "server.json"), sb, 0o644))
	fmt.Println("wrote", dir)
}

func serve(dir string) {
	go func() {
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
		s := &http.Server{Addr: "127.0.0.1:18204", Handler: h, ReadHeaderTimeout: 10 * time.Second}
		log.Fatal(s.ListenAndServe())
	}()
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	must(err)
	s := &http.Server{
		Addr:      "127.0.0.1:18443",
		Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) }),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		ErrorLog:  log.New(os.Stderr, "", 0),
	}
	s.ErrorLog.SetOutput(discard{})
	log.Fatal(s.ListenAndServeTLS("", ""))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func main() {
	if len(os.Args) < 3 {
		log.Fatal("usage: aux setup|serve <dir>")
	}
	switch os.Args[1] {
	case "setup":
		setup(os.Args[2])
	case "serve":
		serve(os.Args[2])
	}
}
