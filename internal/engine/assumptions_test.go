package engine

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/policy"
	"github.com/LatticeNet/lattice-probe/internal/spec"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	sjson "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"
)

// slowResolver answers every name with one address after a delay, like a
// distant recursive resolver.
type slowResolver struct {
	delay time.Duration
	addr  netip.Addr
}

func (r slowResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	select {
	case <-time.After(r.delay):
		return []netip.Addr{r.addr}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// TestServerRTTExcludesNameLookup: server.rtt_ms times the TCP connect
// alone. A server written as a name must not add the lookup to it.
func TestServerRTTExcludesNameLookup(t *testing.T) {
	l := sharedLab(t)
	const delay = 200 * time.Millisecond
	e := newEngine(t, l, func(c *Config) {
		c.Resolver = slowResolver{delay: delay, addr: netip.MustParseAddr("127.0.0.1")}
	})
	ob := l.Outbound("shadowsocks", "", "line")
	ob["server"] = "slow.example"
	raw, _ := json.Marshal(ob)
	res := mustRun(t, e, request(raw))
	if res.Stage != spec.StageOK || !res.Server.Reachable {
		t.Fatalf("stage %s, server %+v, error %q", res.Stage, res.Server, res.Error)
	}
	if res.Server.RTTMS >= float64(delay.Milliseconds())/2 {
		t.Errorf("server rtt %.1f ms includes the %s name lookup", res.Server.RTTMS, delay)
	}
	if res.Server.Address != "slow.example:"+itoa(l.Ports["shadowsocks"]) {
		t.Errorf("server address %q", res.Server.Address)
	}
}

// TestDecoderFoldsFieldNames records why policy.Parse refuses folded field
// names: the sing-box decoder accepts them, at the top level and nested.
// If this starts failing after a sing-box bump, the decoder stopped
// folding and the refusal is merely strict, not wrong.
func TestDecoderFoldsFieldNames(t *testing.T) {
	e := newEngine(t, sharedLab(t))
	raw := []byte(`{"type":"trojan","tag":"x","server":"8.8.8.8","ſerver":"1.1.1.1","server_port":1,"password":"p","tls":{"enabled":true,"certificate_PATH":"/etc/passwd"}}`)
	opt, err := sjson.UnmarshalExtendedContext[option.Outbound](e.ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	trojan := opt.Options.(*option.TrojanOutboundOptions)
	if trojan.Server != "1.1.1.1" {
		t.Errorf("server decoded as %q, want the folded field's value", trojan.Server)
	}
	if trojan.TLS == nil || trojan.TLS.CertificatePath != "/etc/passwd" {
		t.Errorf("tls %+v, want certificate_PATH read as certificate_path", trojan.TLS)
	}
}

// startHookOutbounds is one constructible config per allowed type.
var startHookOutbounds = map[string]string{
	"shadowsocks": `{"method":"2022-blake3-aes-128-gcm","password":"AAAAAAAAAAAAAAAAAAAAAA=="}`,
	"vmess":       `{"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","security":"auto"}`,
	"vless":       `{"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}`,
	"trojan":      `{"password":"p","tls":{"enabled":true,"server_name":"example.com"}}`,
	"hysteria":    `{"up_mbps":10,"down_mbps":10,"auth_str":"p","tls":{"enabled":true,"server_name":"example.com"}}`,
	"hysteria2":   `{"password":"p","tls":{"enabled":true,"server_name":"example.com"}}`,
	"tuic":        `{"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","password":"p","tls":{"enabled":true,"server_name":"example.com"}}`,
	"shadowtls":   `{"version":3,"password":"p","tls":{"enabled":true,"server_name":"example.com"}}`,
	"anytls":      `{"password":"p","tls":{"enabled":true,"server_name":"example.com"}}`,
	"socks":       `{"version":"5"}`,
	"http":        `{}`,
	"ssh":         `{"user":"root","password":"p"}`,
}

// TestAllowedTypesHaveNoStartHook pins an assumption of Run's cleanup. When
// a start hook fails, sing-box's Manager.Create returns the error without
// closing the outbound it built and without registering it, so Run has no
// handle to remove. That is only safe while no allowed type has a start
// hook; a sing-box bump that adds one fails here instead of leaking.
func TestAllowedTypesHaveNoStartHook(t *testing.T) {
	e := newEngine(t, sharedLab(t))
	registry := service.FromContext[adapter.OutboundRegistry](e.ctx)
	types := make([]string, 0, len(policy.AllowedTypes))
	for typ := range policy.AllowedTypes {
		types = append(types, typ)
	}
	sort.Strings(types)
	for _, typ := range types {
		t.Run(typ, func(t *testing.T) {
			body, ok := startHookOutbounds[typ]
			if !ok {
				t.Fatalf("no config for allowed type %s; add one so its start hooks are checked", typ)
			}
			fields := map[string]json.RawMessage{}
			if err := json.Unmarshal([]byte(body), &fields); err != nil {
				t.Fatal(err)
			}
			fields["type"], _ = json.Marshal(typ)
			fields["tag"], _ = json.Marshal("hook-" + typ)
			fields["server"], _ = json.Marshal("1.1.1.1")
			fields["server_port"], _ = json.Marshal(443)
			raw, _ := json.Marshal(fields)
			opt, err := sjson.UnmarshalExtendedContext[option.Outbound](e.ctx, raw)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			ob, err := registry.CreateOutbound(e.ctx, e.box.Router(), e.box.LogFactory().NewLogger("test"), opt.Tag, opt.Type, opt.Options)
			if err != nil {
				t.Fatalf("construct: %v", err)
			}
			defer common.Close(ob)
			if _, ok := ob.(adapter.Lifecycle); ok {
				t.Errorf("%T has Start(stage)", ob)
			}
			if _, ok := ob.(interface{ PreStart() error }); ok {
				t.Errorf("%T has PreStart", ob)
			}
			if _, ok := ob.(interface{ Start() error }); ok {
				t.Errorf("%T has Start", ob)
			}
			if _, ok := ob.(interface{ PostStart() error }); ok {
				t.Errorf("%T has PostStart", ob)
			}
		})
	}
}
