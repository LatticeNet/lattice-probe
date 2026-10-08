package policy

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/spec"
)

func TestCheckRefusesEveryNonGlobalClass(t *testing.T) {
	refused := map[string]string{
		"127.0.0.1":          "loopback",
		"127.255.255.254":    "loopback",
		"10.0.0.1":           "private",
		"172.31.255.255":     "private",
		"192.168.0.1":        "private",
		"100.64.0.1":         "CGNAT",
		"100.127.255.255":    "CGNAT",
		"169.254.169.254":    "link-local",
		"0.0.0.0":            "this network",
		"0.255.0.1":          "this network",
		"224.0.0.251":        "multicast",
		"239.255.255.250":    "multicast",
		"240.0.0.1":          "reserved",
		"255.255.255.255":    "reserved",
		"198.18.0.1":         "benchmarking",
		"192.0.2.1":          "documentation",
		"::":                 "unspecified",
		"::1":                "loopback",
		"fc00::1":            "unique local",
		"fd00:dead::1":       "unique local",
		"fe80::1":            "link-local",
		"ff02::1":            "multicast",
		"::ffff:127.0.0.1":   "loopback",
		"::ffff:10.0.0.1":    "private",
		"64:ff9b::a00:1":     "NAT64 form of 10.0.0.1",
		"64:ff9b::7f00:1":    "NAT64 form of 127.0.0.1",
		"2002:7f00:1::1":     "6to4 form of 127.0.0.1",
		"2002:c0a8:101::1":   "6to4 form of 192.168.1.1",
		"2001:db8::1":        "documentation",
		"100::1":             "discard-only",
		"::200:1":            "outside the IPv6 global unicast range",
		"64:ff9b:1::1":       "local-use NAT64",
		"2001::1":            "IETF protocol assignments",
		"fe80::1%en0":        "scoped to an interface",
		"3fff:0:0:0:0:0:0:1": "documentation",
	}
	p := &Policy{}
	for addr, reason := range refused {
		a := netip.MustParseAddr(addr)
		r := p.Check(a)
		if r == nil {
			t.Errorf("%s passed, want refused as %s", addr, reason)
			continue
		}
		if !strings.Contains(r.Error(), reason) {
			t.Errorf("%s refused with %q, want it to mention %q", addr, r.Error(), reason)
		}
	}
	for _, addr := range []string{"1.1.1.1", "8.8.8.8", "203.0.114.1", "100.128.0.1", "172.32.0.1", "2606:4700::1111", "2a01:4f8::1", "64:ff9b::808:808", "2002:808:808::1"} {
		if r := p.Check(netip.MustParseAddr(addr)); r != nil {
			t.Errorf("%s refused: %v", addr, r)
		}
	}
}

func TestAllowList(t *testing.T) {
	allow, err := ParsePrefixes(" 127.0.0.0/8, 10.1.2.3 ,fd00::/8")
	if err != nil {
		t.Fatal(err)
	}
	p := &Policy{Allow: allow}
	for _, addr := range []string{"127.0.0.1", "10.1.2.3", "fd00::5", "::ffff:127.0.0.9"} {
		if r := p.Check(netip.MustParseAddr(addr)); r != nil {
			t.Errorf("%s refused despite the allowlist: %v", addr, r)
		}
	}
	for _, addr := range []string{"10.1.2.4", "192.168.0.1"} {
		if p.Check(netip.MustParseAddr(addr)) == nil {
			t.Errorf("%s allowed outside the allowlist", addr)
		}
	}
	// The allowlist never opens unspecified or multicast.
	wide := &Policy{Allow: []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}}
	for _, addr := range []string{"0.0.0.0", "224.0.0.1"} {
		if wide.Check(netip.MustParseAddr(addr)) == nil {
			t.Errorf("%s allowed by 0.0.0.0/0", addr)
		}
	}
	if _, err := ParsePrefixes("10.0.0.0/33"); err == nil {
		t.Error("an invalid prefix parsed")
	}
	if got, err := ParsePrefixes(""); err != nil || len(got) != 0 {
		t.Errorf("empty list: %v %v", got, err)
	}
}

func TestDenyList(t *testing.T) {
	deny, err := ParsePrefixes("141.11.77.182, 2001:db9:1::/48")
	if err != nil {
		t.Fatal(err)
	}
	p := &Policy{Deny: deny}
	for _, addr := range []string{
		"141.11.77.182",
		"::ffff:141.11.77.182", // the mapped form
		"64:ff9b::8d0b:4db6",   // the NAT64 form of 141.11.77.182
		"2002:8d0b:4db6::1",    // the 6to4 form of 141.11.77.182
		"2001:db9:1::5",
	} {
		r := p.Check(netip.MustParseAddr(addr))
		if r == nil {
			t.Errorf("%s allowed despite the denylist", addr)
			continue
		}
		if !strings.Contains(r.Reason, "denied by the probe's address policy") {
			t.Errorf("%s: reason %q does not name the denylist", addr, r.Reason)
		}
	}
	for _, addr := range []string{"141.11.77.183", "8.8.8.8", "2001:db9:2::1"} {
		if r := p.Check(netip.MustParseAddr(addr)); r != nil {
			t.Errorf("%s refused outside the denylist: %v", addr, r)
		}
	}
	// Deny wins over Allow.
	both := &Policy{Allow: []netip.Prefix{netip.MustParsePrefix("141.11.77.0/24")}, Deny: deny}
	if both.Check(netip.MustParseAddr("141.11.77.182")) == nil {
		t.Error("an allowed prefix overrode the denylist")
	}
	if both.Check(netip.MustParseAddr("141.11.77.1")) != nil {
		t.Error("the allowlist stopped working next to a denylist")
	}
	// Non-global classes keep their own reason when not denied.
	if r := p.Check(netip.MustParseAddr("127.0.0.1")); r == nil || r.Reason != "loopback" {
		t.Errorf("loopback with a denylist: %v", r)
	}
}

func TestRedact(t *testing.T) {
	raw := map[string]json.RawMessage{}
	_ = json.Unmarshal([]byte(`{"type":"vless","uuid":"0b9c1bd8-aaaa","password":"hunter22","tls":{"reality":{"short_id":"abcd1234","public_key":"PUBLICKEY"}},"headers":{"Authorization":"Bearer tok123456"},"tag":"x"}`), &raw)
	secrets := appendSecrets(nil, raw)
	msg := Redact("bad 0b9c1bd8-aaaa and hunter22 and abcd1234 and Bearer tok123456 near PUBLICKEY", secrets)
	for _, s := range []string{"0b9c1bd8-aaaa", "hunter22", "abcd1234", "tok123456"} {
		if strings.Contains(msg, s) {
			t.Errorf("%q survived redaction: %s", s, msg)
		}
	}
	if !strings.Contains(msg, "PUBLICKEY") {
		t.Errorf("a public key was redacted: %s", msg)
	}
}

func TestParseDefaultsAndChains(t *testing.T) {
	targets := spec.DefaultTargets()
	req := &spec.Request{Outbounds: []json.RawMessage{
		json.RawMessage(`{"type":"trojan","tag":"exit","server":"1.1.1.1","server_port":443,"detour":"mid","password":"p"}`),
		json.RawMessage(`{"type":"shadowsocks","tag":"mid","server":"8.8.8.8","server_port":8388,"detour":"first"}`),
		json.RawMessage(`{"type":"hysteria2","tag":"first","server":"example.com","server_ports":["20000:30000"]}`),
	}, Test: "exit"}
	p, err := Parse(req, targets)
	if err != nil {
		t.Fatal(err)
	}
	if p.Test != 0 || p.Root != 2 {
		t.Errorf("test %d root %d", p.Test, p.Root)
	}
	if got := p.Order; len(got) != 3 || got[0] != 2 || got[1] != 1 || got[2] != 0 {
		t.Errorf("creation order %v, want first, mid, exit", got)
	}
	if p.Outbounds[2].Port != 20000 {
		t.Errorf("server_ports fallback gave %d", p.Outbounds[2].Port)
	}
	if p.Samples != 5 || p.Timeout != 15*time.Second || p.ThroughputBytes != 10_000_000 || len(p.Targets) != 1 || p.Targets[0].ID != "gstatic-204" {
		t.Errorf("defaults: %+v", p)
	}
}

func TestParseRefusesFilePaths(t *testing.T) {
	for _, ob := range []string{
		`{"type":"trojan","tag":"a","server":"1.1.1.1","server_port":1,"tls":{"certificate_path":"/etc/passwd"}}`,
		`{"type":"ssh","tag":"a","server":"1.1.1.1","server_port":22,"private_key_path":"/root/.ssh/id_ed25519"}`,
		`{"type":"vless","tag":"a","server":"1.1.1.1","server_port":1,"tls":{"ech":{"config_path":"/x"}}}`,
		`{"type":"trojan","tag":"a","server":"1.1.1.1","server_port":1,"tls":{"certificate_path":["/a"]}}`,
	} {
		_, err := Parse(&spec.Request{Outbounds: []json.RawMessage{json.RawMessage(ob)}}, spec.DefaultTargets())
		var re *spec.RequestError
		if !errors.As(err, &re) || re.Stage != spec.StagePolicy || !strings.Contains(re.Message, "_path") {
			t.Errorf("%s: %v", ob, err)
		}
	}
	// A boolean that happens to end in _path is not a file.
	ok := `{"type":"vless","tag":"a","server":"1.1.1.1","server_port":1,"tcp_multi_path":true}`
	if _, err := Parse(&spec.Request{Outbounds: []json.RawMessage{json.RawMessage(ok)}}, spec.DefaultTargets()); err != nil {
		t.Errorf("tcp_multi_path refused: %v", err)
	}
}

func TestParseRefusesNonProxyTypes(t *testing.T) {
	for _, typ := range []string{"direct", "block", "dns", "selector", "urltest", "tor", "wireguard", "lattice-guard", "naive"} {
		ob := `{"type":"` + typ + `","tag":"a","server":"1.1.1.1","server_port":1}`
		_, err := Parse(&spec.Request{Outbounds: []json.RawMessage{json.RawMessage(ob)}}, spec.DefaultTargets())
		var re *spec.RequestError
		if !errors.As(err, &re) || re.Stage != spec.StagePolicy {
			t.Errorf("type %s: %v", typ, err)
		}
	}
}

// TestParseRefusesFoldedFieldNames covers names the sing-box decoder
// matches case-insensitively, with Unicode folding, while Parse reads
// fields by exact name: "ſerver" (U+017F) decodes as server, so the
// policy and the decoder would see different servers.
func TestParseRefusesFoldedFieldNames(t *testing.T) {
	for name, ob := range map[string]string{
		"long s beside server": `{"type":"socks","tag":"a","server":"8.8.8.8","ſerver":"1.1.1.1","server_port":1}`,
		"long s in port":       `{"type":"socks","tag":"a","server":"8.8.8.8","server_port":1,"ſerver_port":2}`,
		"long s in a secret":   `{"type":"hysteria2","tag":"a","server":"8.8.8.8","server_port":1,"obfs":{"type":"salamander","paſſword":"hunter22"}}`,
		"kelvin sign":          `{"type":"vless","tag":"a","server":"8.8.8.8","server_port":1,"tls":{"reality":{"public_Key":"x"}}}`,
		"uppercase server":     `{"type":"socks","tag":"a","Server":"1.1.1.1","server":"8.8.8.8","server_port":1}`,
		"uppercase detour":     `{"type":"socks","tag":"a","server":"8.8.8.8","server_port":1,"DETOUR":"b"}`,
	} {
		_, err := Parse(&spec.Request{Outbounds: []json.RawMessage{json.RawMessage(ob)}}, spec.DefaultTargets())
		var re *spec.RequestError
		if !errors.As(err, &re) || re.Stage != spec.StageRequest || !strings.Contains(re.Message, "field name") {
			t.Errorf("%s: %v, want a request refusal naming the field", name, err)
		}
	}
	// Header names are data, not option fields, and keep their case.
	ok := `{"type":"vmess","tag":"a","server":"8.8.8.8","server_port":1,"uuid":"u","transport":{"type":"ws","headers":{"Host":"cdn.example"}}}`
	if _, err := Parse(&spec.Request{Outbounds: []json.RawMessage{json.RawMessage(ok)}}, spec.DefaultTargets()); err != nil {
		t.Errorf("a mixed-case header name was refused: %v", err)
	}
}

// TestParseRefusesFoldedFilePaths: the decoder reads certificate_PATH into
// certificate_path, so the file check must not depend on case either.
func TestParseRefusesFoldedFilePaths(t *testing.T) {
	ob := `{"type":"trojan","tag":"a","server":"1.1.1.1","server_port":1,"tls":{"enabled":true,"certificate_PATH":"/etc/passwd"}}`
	_, err := Parse(&spec.Request{Outbounds: []json.RawMessage{json.RawMessage(ob)}}, spec.DefaultTargets())
	var re *spec.RequestError
	if !errors.As(err, &re) || re.Stage != spec.StagePolicy || !strings.Contains(re.Message, "certificate_PATH") {
		t.Errorf("%v, want a policy refusal of tls.certificate_PATH", err)
	}
}
