// Engine A: one sing-box box.Box, outbounds created and removed per test
// through the outbound manager.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"benchharness"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type engine struct {
	ctx  context.Context
	inst *box.Box
}

type outbound struct {
	e   *engine
	tag string
	ob  adapter.Outbound
}

func (e *engine) Name() string   { return "sing-box" }
func (e *engine) Module() string { return "github.com/sagernet/sing-box" }
func (e *engine) Notes() map[string]any {
	return map[string]any{
		"create":  "sing/common/json.UnmarshalExtendedContext[option.Outbound](include ctx, text) -> Outbound().Create(ctx, Router(), logger, tag, type, options)",
		"dial":    "Outbound().Outbound(tag) as N.Dialer: DialContext(ctx, tcp, socksaddr)",
		"release": "Outbound().Remove(tag) (closes the outbound because the manager is started)",
		"urltest": "common/urltest.URLTest(ctx, url, outbound)",
		"start":   "include.Context + box.New(log disabled, one direct outbound) + Start()",
	}
}

func (e *engine) Start() error {
	ctx := include.Context(context.Background())
	inst, err := box.New(box.Options{
		Context: ctx,
		Options: option.Options{
			Log:       &option.LogOptions{Disabled: true},
			Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}},
		},
	})
	if err != nil {
		return err
	}
	if err := inst.Start(); err != nil {
		return err
	}
	e.ctx, e.inst = ctx, inst
	return nil
}

func (e *engine) Config(r harness.Resolved) ([]byte, error) {
	m := map[string]any{"server": r.Server, "server_port": r.Port}
	insecureTLS := func(alpn ...string) map[string]any {
		t := map[string]any{"enabled": true, "server_name": r.SNI, "insecure": true}
		if len(alpn) > 0 {
			t["alpn"] = alpn
		}
		return t
	}
	switch r.Proto {
	case "ss":
		m["type"], m["method"], m["password"] = "shadowsocks", "2022-blake3-aes-128-gcm", r.SSKey
	case "vmess_ws":
		m["type"], m["uuid"], m["alter_id"], m["security"] = "vmess", r.UUID, 0, "aes-128-gcm"
		m["transport"] = map[string]any{"type": "ws", "path": r.WSPath}
	case "vless_reality":
		m["type"], m["uuid"], m["flow"] = "vless", r.UUID, "xtls-rprx-vision"
		m["tls"] = map[string]any{
			"enabled": true, "server_name": r.SNI,
			"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
			"reality": map[string]any{"enabled": true, "public_key": r.PublicKey, "short_id": r.ShortID},
		}
	case "trojan_tls":
		m["type"], m["password"], m["tls"] = "trojan", r.Password, insecureTLS()
	case "hysteria2":
		m["type"], m["password"], m["tls"] = "hysteria2", r.Password, insecureTLS("h3")
	case "tuic":
		m["type"], m["uuid"], m["password"] = "tuic", r.UUID, r.Password
		m["congestion_control"], m["udp_relay_mode"], m["tls"] = "bbr", "native", insecureTLS("h3")
	default:
		return nil, fmt.Errorf("unknown proto %s", r.Proto)
	}
	return json.Marshal(m)
}

func (e *engine) Create(tag string, cfg []byte) (harness.Outbound, error) {
	opt, err := sjson.UnmarshalExtendedContext[option.Outbound](e.ctx, cfg)
	if err != nil {
		return nil, err
	}
	logger := e.inst.LogFactory().NewLogger("outbound/" + opt.Type + "[" + tag + "]")
	if err := e.inst.Outbound().Create(e.ctx, e.inst.Router(), logger, tag, opt.Type, opt.Options); err != nil {
		return nil, err
	}
	ob, ok := e.inst.Outbound().Outbound(tag)
	if !ok {
		return nil, fmt.Errorf("outbound %s missing after create", tag)
	}
	return &outbound{e: e, tag: tag, ob: ob}, nil
}

func (o *outbound) Dial(ctx context.Context, addr string) (net.Conn, error) {
	return o.ob.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(addr))
}

func (o *outbound) Remove() error { return o.e.inst.Outbound().Remove(o.tag) }

func (e *engine) URLTest(ctx context.Context, ob harness.Outbound, url string) (uint16, error) {
	return urltest.URLTest(ctx, url, ob.(*outbound).ob)
}

func main() {
	entry := time.Now()
	harness.Main(entry, &engine{})
}
