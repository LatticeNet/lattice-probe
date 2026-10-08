package engine

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/policy"
	"github.com/LatticeNet/lattice-probe/internal/spec"
	"github.com/LatticeNet/lattice-probe/internal/testkit"
)

var (
	labOnce sync.Once
	lab     *testkit.Lab
	labErr  error
)

// sharedLab starts one lab for the whole package; its servers are
// stateless, and starting six inbounds per test would dominate the run.
func sharedLab(t testing.TB) *testkit.Lab {
	t.Helper()
	labOnce.Do(func() { lab, labErr = testkit.Start() })
	if labErr != nil {
		t.Fatalf("start lab: %v", labErr)
	}
	return lab
}

func TestMain(m *testing.M) {
	code := m.Run()
	if lab != nil {
		lab.Close()
	}
	os.Exit(code)
}

type engineOption func(*Config)

func newEngine(t testing.TB, l *testkit.Lab, opts ...engineOption) *Engine {
	t.Helper()
	cfg := Config{
		Targets:       l.Targets(),
		Policy:        &policy.Policy{Allow: testkit.LoopbackOnly},
		TraceURL:      l.TraceURL(),
		DNSServer:     l.DNSAddr,
		DNSName:       "lab.test",
		ThroughputURL: l.DownloadURL(),
		SampleTimeout: 2 * time.Second,
	}
	for _, o := range opts {
		o(&cfg)
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func request(outbounds ...json.RawMessage) *spec.Request {
	return &spec.Request{Outbounds: outbounds, Targets: []string{"lab-204"}, Samples: 3, TimeoutMS: 10000}
}

func mustRun(t *testing.T, e *Engine, req *spec.Request) *spec.Result {
	t.Helper()
	res, err := e.Run(context.Background(), req)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return res
}

func TestEveryProtocolPasses(t *testing.T) {
	l := sharedLab(t)
	e := newEngine(t, l)
	for _, proto := range testkit.Protocols {
		t.Run(proto, func(t *testing.T) {
			req := request(l.OutboundJSON(proto, "", "line"))
			req.UDP = true
			req.Targets = []string{"lab-204", "lab-200"}
			res := mustRun(t, e, req)
			if !res.Valid || res.Stage != spec.StageOK {
				t.Fatalf("stage %s, error %q", res.Stage, res.Error)
			}
			if !res.Server.Reachable || res.Server.RTTMS < 0 {
				t.Errorf("server not reachable: %+v", res.Server)
			}
			wantNetwork := "tcp"
			if proto == "hysteria2" || proto == "tuic" {
				wantNetwork = "udp"
			}
			if res.Server.Network != wantNetwork {
				t.Errorf("server network %q, want %q", res.Server.Network, wantNetwork)
			}
			if len(res.Targets) != 2 {
				t.Fatalf("targets %+v", res.Targets)
			}
			for _, tr := range res.Targets {
				if tr.OK != 3 || tr.Of != 3 || tr.Error != "" {
					t.Errorf("target %s: %d/%d %q", tr.ID, tr.OK, tr.Of, tr.Error)
				}
				// Loopback delays can round to 0.0 ms; order is what must hold.
				if tr.ColdMS.Min < 0 || tr.ColdMS.P50 < tr.ColdMS.Min || tr.ColdMS.P90 < tr.ColdMS.P50 {
					t.Errorf("target %s cold %+v", tr.ID, tr.ColdMS)
				}
				if tr.WarmMS.P50 < tr.WarmMS.Min || tr.WarmMS.P90 < tr.WarmMS.P50 {
					t.Errorf("target %s warm %+v", tr.ID, tr.WarmMS)
				}
			}
			if res.Exit == nil || res.Exit.IP != "127.0.0.1" || res.Exit.Colo != "LAB" {
				t.Errorf("exit %+v", res.Exit)
			}
			if res.UDP == nil || !res.UDP.OK || res.UDP.Error != "" {
				t.Errorf("udp %+v", res.UDP)
			}
			if res.Throughput != nil {
				t.Errorf("throughput ran without being asked: %+v", res.Throughput)
			}
			if res.Engine.Name != "sing-box" || res.Engine.Version != "1.13.19" {
				t.Errorf("engine %+v", res.Engine)
			}
		})
	}
	if n := e.outboundCount(); n != 1 {
		t.Errorf("%d outbounds left, want only direct", n)
	}
}

func TestThroughput(t *testing.T) {
	l := sharedLab(t)
	e := newEngine(t, l)
	req := request(l.OutboundJSON("shadowsocks", "", "line"))
	req.Throughput, req.ThroughputBytes = true, 2_000_000
	res := mustRun(t, e, req)
	if res.Stage != spec.StageOK || res.Throughput == nil {
		t.Fatalf("stage %s, throughput %+v, error %q", res.Stage, res.Throughput, res.Error)
	}
	if res.Throughput.Bytes != 2_000_000 || res.Throughput.Mbps <= 0 {
		t.Errorf("throughput %+v", res.Throughput)
	}
}

func TestWrongCredentialsFailFast(t *testing.T) {
	l := sharedLab(t)
	e := newEngine(t, l)
	cases := []struct{ proto, variant string }{
		{"shadowsocks", "wrong"},
		{"vmess", "wrong"},
		{"vless", "wrong"},
		{"vless", "wrong-short-id"},
		{"trojan", "wrong"},
		{"hysteria2", "wrong"},
		{"tuic", "wrong"},
	}
	for _, c := range cases {
		t.Run(c.proto+"/"+c.variant, func(t *testing.T) {
			start := time.Now()
			res := mustRun(t, e, request(l.OutboundJSON(c.proto, c.variant, "line")))
			took := time.Since(start)
			if !res.Valid {
				t.Fatalf("a wrong credential is still a valid config: %+v", res)
			}
			if res.Stage != spec.StageHandshake {
				t.Fatalf("stage %s, want handshake (error %q)", res.Stage, res.Error)
			}
			if res.Error == "" {
				t.Error("no error text")
			}
			if !res.Server.Reachable {
				t.Errorf("server check failed for a running server: %+v", res.Server)
			}
			if took > 2*time.Second {
				t.Errorf("took %s, a wrong credential must fail fast", took)
			}
			if res.Targets[0].OK != 0 {
				t.Errorf("target passed with a wrong credential: %+v", res.Targets[0])
			}
		})
	}
}

func TestStages(t *testing.T) {
	l := sharedLab(t)
	e := newEngine(t, l)

	t.Run("decode", func(t *testing.T) {
		ob := l.Outbound("vmess", "", "line")
		ob["alter_id"] = "not a number"
		raw, _ := json.Marshal(ob)
		res := mustRun(t, e, request(raw))
		if res.Valid || res.Stage != spec.StageDecode || res.Error == "" {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("create", func(t *testing.T) {
		ob := l.Outbound("shadowsocks", "", "line")
		ob["method"] = "no-such-cipher"
		raw, _ := json.Marshal(ob)
		res := mustRun(t, e, request(raw))
		if res.Valid || res.Stage != spec.StageCreate || res.Error == "" {
			t.Fatalf("%+v", res)
		}
	})
	t.Run("server refused", func(t *testing.T) {
		port, err := closedPort()
		if err != nil {
			t.Fatal(err)
		}
		ob := l.Outbound("trojan", "", "line")
		ob["server_port"] = port
		raw, _ := json.Marshal(ob)
		start := time.Now()
		res := mustRun(t, e, request(raw))
		if !res.Valid || res.Stage != spec.StageServer || res.Server.Reachable {
			t.Fatalf("%+v", res)
		}
		if len(res.Targets) != 0 {
			t.Errorf("targets ran against a closed port: %+v", res.Targets)
		}
		if time.Since(start) > time.Second {
			t.Errorf("a refused connect took %s", time.Since(start))
		}
	})
	t.Run("quic server down", func(t *testing.T) {
		port, err := closedUDPPort()
		if err != nil {
			t.Fatal(err)
		}
		ob := l.Outbound("hysteria2", "", "line")
		ob["server_port"] = port
		raw, _ := json.Marshal(ob)
		res := mustRun(t, newEngine(t, l, func(c *Config) { c.SampleTimeout = 500 * time.Millisecond }), request(raw))
		if !res.Valid || res.Stage != spec.StageServer || res.Server.Reachable || res.Server.Network != "udp" {
			t.Fatalf("stage %s, server %+v, error %q", res.Stage, res.Server, res.Error)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		host, port := splitHostPort(t, l.Blackhole)
		ob := l.Outbound("vless", "", "line")
		ob["server"], ob["server_port"] = host, port
		raw, _ := json.Marshal(ob)
		res := mustRun(t, newEngine(t, l, func(c *Config) { c.SampleTimeout = 300 * time.Millisecond }), request(raw))
		if !res.Valid || res.Stage != spec.StageTimeout {
			t.Fatalf("stage %s, error %q", res.Stage, res.Error)
		}
		if !res.Server.Reachable {
			t.Errorf("the blackhole accepts TCP, so the server check should pass: %+v", res.Server)
		}
	})
	t.Run("target status", func(t *testing.T) {
		req := request(l.OutboundJSON("shadowsocks", "", "line"))
		req.Targets = []string{"lab-204", "lab-wrong-status"}
		res := mustRun(t, e, req)
		if res.Stage != spec.StageTarget {
			t.Fatalf("stage %s, error %q", res.Stage, res.Error)
		}
		if res.Targets[0].OK != 3 || res.Targets[1].OK != 0 || res.Targets[1].Status != 200 {
			t.Errorf("targets %+v", res.Targets)
		}
	})
	t.Run("chain", func(t *testing.T) {
		// The relay is a shadowsocks hop; the exit trojan line is reached
		// through it, so the server check targets the relay.
		relay := l.Outbound("shadowsocks", "", "relay")
		exit := l.Outbound("trojan", "", "exit")
		exit["detour"] = "relay"
		rawRelay, _ := json.Marshal(relay)
		rawExit, _ := json.Marshal(exit)
		req := request(rawExit, rawRelay)
		req.Test = "exit"
		res := mustRun(t, e, req)
		if res.Stage != spec.StageOK {
			t.Fatalf("stage %s, error %q", res.Stage, res.Error)
		}
		if res.Server.Address != relay["server"].(string)+":"+itoa(relay["server_port"].(int)) {
			t.Errorf("server check went to %s, want the relay", res.Server.Address)
		}
	})
	if n := e.outboundCount(); n != 1 {
		t.Errorf("%d outbounds left, want only direct", n)
	}
}

func TestRefusals(t *testing.T) {
	l := sharedLab(t)
	strict := newEngine(t, l, func(c *Config) { c.Policy = &policy.Policy{} })
	addresses := []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "100.64.0.1",
		"169.254.169.254", "224.0.0.1", "0.0.0.0", "0.1.2.3", "255.255.255.255",
		"::1", "fc00::1", "fd12::1", "fe80::1", "ff02::1", "::", "::ffff:127.0.0.1",
	}
	for _, addr := range addresses {
		t.Run(addr, func(t *testing.T) {
			ob := l.Outbound("shadowsocks", "", "line")
			ob["server"] = addr
			raw, _ := json.Marshal(ob)
			_, err := strict.Run(context.Background(), request(raw))
			assertRefused(t, err, spec.StagePolicy)
		})
	}

	e := newEngine(t, l)
	cases := map[string]func() *spec.Request{
		"foreign detour": func() *spec.Request {
			ob := l.Outbound("shadowsocks", "", "line")
			ob["detour"] = "direct"
			raw, _ := json.Marshal(ob)
			return request(raw)
		},
		"bad target id": func() *spec.Request {
			req := request(l.OutboundJSON("shadowsocks", "", "line"))
			req.Targets = []string{"https://example.com/"}
			return req
		},
		"direct type": func() *spec.Request {
			return request(json.RawMessage(`{"type":"direct","tag":"d","server":"1.1.1.1","server_port":1}`))
		},
		"selector type": func() *spec.Request {
			return request(json.RawMessage(`{"type":"selector","tag":"s","server":"1.1.1.1","server_port":1,"outbounds":["x"]}`))
		},
		"certificate path": func() *spec.Request {
			ob := l.Outbound("trojan", "", "line")
			ob["tls"].(map[string]any)["certificate_path"] = "/etc/passwd"
			raw, _ := json.Marshal(ob)
			return request(raw)
		},
		"too many outbounds": func() *spec.Request {
			var obs []json.RawMessage
			for i := range 9 {
				obs = append(obs, l.OutboundJSON("shadowsocks", "", "t"+itoa(i)))
			}
			req := request(obs...)
			req.Test = "t0"
			return req
		},
		"samples": func() *spec.Request {
			req := request(l.OutboundJSON("shadowsocks", "", "line"))
			req.Samples = 11
			return req
		},
		"timeout": func() *spec.Request {
			req := request(l.OutboundJSON("shadowsocks", "", "line"))
			req.TimeoutMS = 999
			return req
		},
		"throughput cap": func() *spec.Request {
			req := request(l.OutboundJSON("shadowsocks", "", "line"))
			req.Throughput, req.ThroughputBytes = true, 25_000_001
			return req
		},
		"detour cycle": func() *spec.Request {
			a := l.Outbound("shadowsocks", "", "a")
			b := l.Outbound("shadowsocks", "", "b")
			a["detour"], b["detour"] = "b", "a"
			ra, _ := json.Marshal(a)
			rb, _ := json.Marshal(b)
			req := request(ra, rb)
			req.Test = "a"
			return req
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := e.Run(context.Background(), build())
			assertRefused(t, err, spec.StagePolicy)
		})
	}

	malformed := map[string]*spec.Request{
		"no outbounds":  {},
		"not an object": request(json.RawMessage(`"vless://..."`)),
		"missing tag":   request(json.RawMessage(`{"type":"shadowsocks","server":"1.1.1.1","server_port":1}`)),
		"missing port":  request(json.RawMessage(`{"type":"shadowsocks","tag":"x","server":"1.1.1.1"}`)),
		"unknown test": func() *spec.Request {
			r := request(l.OutboundJSON("shadowsocks", "", "line"))
			r.Test = "nope"
			return r
		}(),
		"duplicate tags": func() *spec.Request {
			return withTest(request(l.OutboundJSON("trojan", "", "x"), l.OutboundJSON("tuic", "", "x")), "x")
		}(),
		"test not chosen": request(l.OutboundJSON("trojan", "", "x"), l.OutboundJSON("tuic", "", "y")),
	}
	for name, req := range malformed {
		t.Run(name, func(t *testing.T) {
			_, err := e.Run(context.Background(), req)
			assertRefused(t, err, spec.StageRequest)
		})
	}
	if n := strict.outboundCount() + e.outboundCount(); n != 2 {
		t.Errorf("%d outbounds left across two engines, want two direct ones", n)
	}
}

// rebindingResolver answers a public address the first time a name is
// looked up and loopback ever after, the classic DNS rebinding pattern.
type rebindingResolver struct {
	mu    sync.Mutex
	calls int
}

func (r *rebindingResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls++
	if r.calls == 1 {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

// TestRebindingRefusedAtDialTime proves the dial path enforces the policy
// on its own: the parse-time check sees a public address, the name then
// resolves to loopback, and the guard refuses it before connecting.
func TestRebindingRefusedAtDialTime(t *testing.T) {
	l := sharedLab(t)
	resolver := &rebindingResolver{}
	e := newEngine(t, l, func(c *Config) {
		c.Policy = &policy.Policy{}
		c.Resolver = resolver
	})
	ln, accepted := countingListener(t)
	_, port := splitHostPort(t, ln)
	ob := l.Outbound("shadowsocks", "", "line")
	ob["server"], ob["server_port"] = "rebind.example", port
	raw, _ := json.Marshal(ob)
	_, err := e.Run(context.Background(), request(raw))
	assertRefused(t, err, spec.StagePolicy)
	var re *spec.RequestError
	errors.As(err, &re)
	if !contains(re.Message, "refused at dial time") || !contains(re.Message, "127.0.0.1") {
		t.Errorf("message %q does not say the dial was refused", re.Message)
	}
	if resolver.calls < 2 {
		t.Errorf("resolver called %d times; the guard must resolve on its own", resolver.calls)
	}
	if n := accepted(); n != 0 {
		t.Errorf("the loopback listener accepted %d connections", n)
	}
	if n := e.outboundCount(); n != 1 {
		t.Errorf("%d outbounds left after a refusal", n)
	}
}

// TestGuardControlHook proves the socket-level check: even a dial that
// skips name resolution entirely is refused inside connect.
func TestGuardControlHook(t *testing.T) {
	ln, accepted := countingListener(t)
	st := newGuardState(&policy.Policy{}, &rebindingResolver{})
	_, err := st.dialer.DialContext(context.Background(), "tcp", ln)
	var refusal *policy.Refusal
	if !errors.As(err, &refusal) || !refusal.DialTime {
		t.Fatalf("dial to %s: %v, want a dial-time refusal", ln, err)
	}
	if st.Refused() == nil {
		t.Error("the refusal was not recorded")
	}
	if n := accepted(); n != 0 {
		t.Errorf("the listener accepted %d connections", n)
	}
}

func withTest(r *spec.Request, test string) *spec.Request {
	r.Test = test
	return r
}

func assertRefused(t *testing.T, err error, stage spec.Stage) {
	t.Helper()
	var re *spec.RequestError
	if !errors.As(err, &re) {
		t.Fatalf("got %v, want a %s refusal", err, stage)
	}
	if re.Stage != stage {
		t.Fatalf("stage %s (%s), want %s", re.Stage, re.Message, stage)
	}
}
