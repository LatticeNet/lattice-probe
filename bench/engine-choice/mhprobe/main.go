// Engine B: mihomo adapters parsed per test with adapter.ParseProxy.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"

	"benchharness"

	"github.com/metacubex/mihomo/adapter"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/log"
)

type engine struct{}

type outbound struct{ p C.Proxy }

func (e *engine) Name() string   { return "mihomo" }
func (e *engine) Module() string { return "github.com/metacubex/mihomo" }
func (e *engine) Notes() map[string]any {
	return map[string]any{
		"create":  "encoding/json text -> map[string]any -> adapter.ParseProxy(map)",
		"dial":    "C.Proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP, DstPort})",
		"release": "C.Proxy.Close() (ParseProxy wraps every adapter in autoCloseProxyAdapter, whose Close calls the adapter's Close once and clears its finalizer)",
		"urltest": "C.Proxy.URLTest(ctx, url, nil); UnifiedDelay left at default false",
		"start":   "log.SetLevel(log.SILENT); no other global init",
	}
}

func (e *engine) Start() error {
	log.SetLevel(log.SILENT)
	return nil
}

func (e *engine) Config(r harness.Resolved) ([]byte, error) {
	m := map[string]any{"server": r.Server, "port": r.Port}
	switch r.Proto {
	case "ss":
		m["type"], m["cipher"], m["password"] = "ss", "2022-blake3-aes-128-gcm", r.SSKey
	case "vmess_ws":
		m["type"], m["uuid"], m["alterId"], m["cipher"] = "vmess", r.UUID, 0, "aes-128-gcm"
		m["network"], m["ws-opts"] = "ws", map[string]any{"path": r.WSPath}
	case "vless_reality":
		m["type"], m["uuid"], m["flow"], m["network"] = "vless", r.UUID, "xtls-rprx-vision", "tcp"
		m["tls"], m["servername"], m["client-fingerprint"] = true, r.SNI, "chrome"
		m["reality-opts"] = map[string]any{"public-key": r.PublicKey, "short-id": r.ShortID}
	case "trojan_tls":
		m["type"], m["password"], m["sni"], m["skip-cert-verify"] = "trojan", r.Password, r.SNI, true
	case "hysteria2":
		m["type"], m["password"], m["sni"], m["skip-cert-verify"] = "hysteria2", r.Password, r.SNI, true
		m["alpn"] = []string{"h3"}
	case "tuic":
		m["type"], m["uuid"], m["password"], m["sni"], m["skip-cert-verify"] = "tuic", r.UUID, r.Password, r.SNI, true
		m["alpn"], m["congestion-controller"], m["udp-relay-mode"] = []string{"h3"}, "bbr", "native"
	default:
		return nil, fmt.Errorf("unknown proto %s", r.Proto)
	}
	return json.Marshal(m)
}

func (e *engine) Create(tag string, cfg []byte) (harness.Outbound, error) {
	var m map[string]any
	if err := json.Unmarshal(cfg, &m); err != nil {
		return nil, err
	}
	m["name"] = tag
	p, err := adapter.ParseProxy(m)
	if err != nil {
		return nil, err
	}
	return &outbound{p}, nil
}

func (o *outbound) Dial(ctx context.Context, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	pn, _ := strconv.Atoi(port)
	md := &C.Metadata{NetWork: C.TCP, Type: C.INNER, DstPort: uint16(pn)}
	if ip, err := netip.ParseAddr(host); err == nil {
		md.DstIP = ip
	} else {
		md.Host = host
	}
	return o.p.DialContext(ctx, md)
}

func (o *outbound) Remove() error { return o.p.Close() }

func (e *engine) URLTest(ctx context.Context, ob harness.Outbound, url string) (uint16, error) {
	return ob.(*outbound).p.URLTest(ctx, url, nil)
}

func main() {
	entry := time.Now()
	harness.Main(entry, &engine{})
}
