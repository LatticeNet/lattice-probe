package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/LatticeNet/lattice-probe/internal/policy"
	"github.com/LatticeNet/lattice-probe/internal/spec"
	"github.com/LatticeNet/lattice-probe/internal/testkit"
)

// labHTTP lets custom targets reach the lab's plain-HTTP server on
// loopback, as a lab deployment would with LATTICE_PROBE_ALLOW_HTTP_TARGETS.
func labHTTP(c *Config) { c.AllowHTTPTargets = true }

func customRequest(l *testkit.Lab, targets ...spec.CustomTarget) *spec.Request {
	req := request(l.OutboundJSON("shadowsocks", "", "line"))
	req.Targets = nil
	for _, t := range targets {
		req.Targets = append(req.Targets, t.ID)
	}
	req.CustomTargets = targets
	return req
}

func TestCustomTargetsMeasure(t *testing.T) {
	l := sharedLab(t)
	e := newEngine(t, l, labHTTP)
	base := "http://" + l.HTTPAddr
	req := customRequest(l,
		spec.CustomTarget{ID: "custom-range", URL: base + "/generate_204", Method: "GET", ExpectStatus: "200-299"},
		spec.CustomTarget{ID: "custom-head", URL: base + "/ok", Method: "HEAD", ExpectStatus: "200"},
		spec.CustomTarget{ID: "custom-body", URL: base + "/ok", Method: "GET", ExpectStatus: "200", BodyContains: "ok"},
	)
	req.Targets = append(req.Targets, "lab-204")
	res := mustRun(t, e, req)
	if res.Stage != spec.StageOK {
		t.Fatalf("stage %s: %s %+v", res.Stage, res.Error, res.Targets)
	}
	if len(res.Targets) != 4 {
		t.Fatalf("targets %+v", res.Targets)
	}
	for _, tr := range res.Targets {
		if tr.OK != 3 || tr.Of != 3 || tr.Error != "" {
			t.Errorf("%s: %+v", tr.ID, tr)
		}
	}
	if m := res.Targets[2].BodyMatch; m == nil || !*m {
		t.Errorf("body target: body_match %v", m)
	}
	if res.Targets[0].BodyMatch != nil || res.Targets[3].BodyMatch != nil {
		t.Error("body_match set on a target without a needle")
	}
}

func TestCustomTargetsFail(t *testing.T) {
	l := sharedLab(t)
	e := newEngine(t, l, labHTTP)
	base := "http://" + l.HTTPAddr
	res := mustRun(t, e, customRequest(l,
		spec.CustomTarget{ID: "custom-status", URL: base + "/ok", Method: "GET", ExpectStatus: "204,301-308"},
		spec.CustomTarget{ID: "custom-text", URL: base + "/ok", Method: "GET", ExpectStatus: "200", BodyContains: "Success"},
	))
	if res.Stage != spec.StageTarget || len(res.Targets) != 2 {
		t.Fatalf("stage %s targets %+v", res.Stage, res.Targets)
	}
	status, text := res.Targets[0], res.Targets[1]
	if status.OK != 0 || status.Status != 200 || !contains(status.Error, "want 204,301-308") {
		t.Errorf("status target %+v", status)
	}
	if text.OK != 0 || text.Status != 200 || text.BodyMatch == nil || *text.BodyMatch || !contains(text.Error, "did not contain the expected text") {
		t.Errorf("text target %+v", text)
	}
	if contains(text.Error, "ok") {
		t.Errorf("the error %q quotes the body", text.Error)
	}
}

// TestCustomTargetsOffByDefault: http stays refused unless the deployment
// allows it, and loopback stays refused unless the policy allows it.
func TestCustomTargetsOffByDefault(t *testing.T) {
	l := sharedLab(t)
	target := spec.CustomTarget{ID: "custom-lab", URL: "http://" + l.HTTPAddr + "/generate_204", Method: "GET", ExpectStatus: "204"}
	_, err := newEngine(t, l).Run(context.Background(), customRequest(l, target))
	assertRefused(t, err, spec.StagePolicy)
	strict := newEngine(t, l, labHTTP, func(c *Config) { c.Policy = &policy.Policy{} })
	_, err = strict.Run(context.Background(), customRequest(l, target))
	assertRefused(t, err, spec.StagePolicy)
	var re *spec.RequestError
	if errors.As(err, &re) && !contains(re.Message, "loopback") {
		t.Errorf("message %q does not name loopback", re.Message)
	}
}

// fixedResolver answers every name with the same addresses and counts calls.
type fixedResolver struct {
	addrs []netip.Addr
	err   error
	calls atomic.Int64
}

func (r *fixedResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.calls.Add(1)
	return r.addrs, r.err
}

// TestCustomTargetResolutionHint: a name that resolves on the probe to a
// refused address, or does not resolve, is refused before anything is
// created or dialled.
func TestCustomTargetResolutionHint(t *testing.T) {
	l := sharedLab(t)
	cases := map[string]struct {
		resolver *fixedResolver
		deny     []netip.Prefix
		want     string
	}{
		"private answer": {resolver: &fixedResolver{addrs: []netip.Addr{netip.MustParseAddr("10.0.0.7")}}, want: "refuses"},
		"one bad answer among good": {resolver: &fixedResolver{addrs: []netip.Addr{netip.MustParseAddr("8.8.4.4"), netip.MustParseAddr("192.168.1.9")}},
			want: "refuses"},
		"denied answer": {resolver: &fixedResolver{addrs: []netip.Addr{netip.MustParseAddr("8.8.8.8")}}, deny: []netip.Prefix{netip.MustParsePrefix("8.8.8.0/24")},
			want: "refuses"},
		"no answer":    {resolver: &fixedResolver{}, want: "does not resolve"},
		"lookup fails": {resolver: &fixedResolver{err: errors.New("no such host")}, want: "does not resolve"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			e := newEngine(t, l, func(cfg *Config) {
				cfg.Resolver = c.resolver
				cfg.Policy = &policy.Policy{Allow: testkit.LoopbackOnly, Deny: c.deny}
			})
			ln, accepted := countingListener(t)
			_, port := splitHostPort(t, ln)
			ob := l.Outbound("shadowsocks", "", "line")
			ob["server_port"] = port
			raw, _ := json.Marshal(ob)
			req := customRequest(l, spec.CustomTarget{ID: "custom-edge", URL: "https://edge.example.net/", Method: "GET", ExpectStatus: "204"})
			req.Outbounds = []json.RawMessage{raw}
			_, err := e.Run(context.Background(), req)
			assertRefused(t, err, spec.StagePolicy)
			var re *spec.RequestError
			if errors.As(err, &re) && (!contains(re.Message, c.want) || !contains(re.Message, "custom-edge")) {
				t.Errorf("message %q, want it to name custom-edge and %q", re.Message, c.want)
			}
			for _, a := range c.resolver.addrs {
				if re != nil && contains(re.Message, a.String()) {
					t.Errorf("message %q reveals the resolver's answer %s", re.Message, a)
				}
			}
			if c.resolver.calls.Load() == 0 {
				t.Error("the resolver was not consulted")
			}
			if n := accepted(); n != 0 {
				t.Errorf("%d connections reached the listener", n)
			}
			if n := e.outboundCount(); n != 1 {
				t.Errorf("%d outbounds left after a refusal", n)
			}
		})
	}
}

// TestCustomTargetHostsResolvedOnce: two targets on one name cost one lookup.
func TestCustomTargetHostsResolvedOnce(t *testing.T) {
	l := sharedLab(t)
	resolver := &fixedResolver{}
	e := newEngine(t, l, func(cfg *Config) { cfg.Resolver = resolver })
	req := customRequest(l,
		spec.CustomTarget{ID: "custom-a", URL: "https://edge.example.net/a", Method: "GET", ExpectStatus: "204"},
		spec.CustomTarget{ID: "custom-b", URL: "https://edge.example.net/b", Method: "GET", ExpectStatus: "204"},
	)
	_, err := e.Run(context.Background(), req)
	assertRefused(t, err, spec.StagePolicy)
	if n := resolver.calls.Load(); n != 1 {
		t.Errorf("%d lookups for one name", n)
	}
}
