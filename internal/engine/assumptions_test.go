package engine

import (
	"context"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/spec"

	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
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
