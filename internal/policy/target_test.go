package policy

import (
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/LatticeNet/lattice-probe/internal/spec"
)

func custom(id, url string) spec.CustomTarget {
	return spec.CustomTarget{ID: id, URL: url, Method: "GET", ExpectStatus: "204"}
}

func TestCheckCustomTargetAccepts(t *testing.T) {
	cases := map[string]struct {
		target spec.CustomTarget
		rules  TargetRules
		host   string
		expect string
	}{
		"plain https":       {custom("custom-a", "https://example.net/generate_204"), TargetRules{}, "example.net", "204"},
		"explicit 443":      {custom("custom-a", "https://example.net:443/"), TargetRules{}, "example.net", "204"},
		"high port":         {custom("custom-a", "https://edge.example.net:8443/health?x=1&y=%20z"), TargetRules{}, "edge.example.net", "204"},
		"upper case host":   {custom("custom-a", "https://Example.NET/"), TargetRules{}, "example.net", "204"},
		"punycode host":     {custom("custom-a", "https://xn--bcher-kva.ch/"), TargetRules{}, "xn--bcher-kva.ch", "204"},
		"global v4 literal": {custom("custom-a", "https://1.1.1.1/"), TargetRules{}, "", "204"},
		"global v6 literal": {custom("custom-a", "https://[2606:4700:4700::1111]:8443/"), TargetRules{}, "", "204"},
		"status ranges": {spec.CustomTarget{ID: "custom-a", URL: "https://example.net/", Method: "GET", ExpectStatus: "200-299,301"},
			TargetRules{}, "example.net", "200-299,301"},
		"head": {spec.CustomTarget{ID: "custom-a", URL: "https://example.net/", Method: "HEAD", ExpectStatus: "200"},
			TargetRules{}, "example.net", "200"},
		"body needle": {spec.CustomTarget{ID: "custom-a", URL: "https://example.net/", Method: "GET", ExpectStatus: "200", BodyContains: "Success é"},
			TargetRules{}, "example.net", "200"},
		"http when allowed":     {custom("custom-a", "http://example.net/"), TargetRules{AllowHTTP: true}, "example.net", "204"},
		"http port 80":          {custom("custom-a", "http://example.net:80/"), TargetRules{AllowHTTP: true}, "example.net", "204"},
		"allowed lab literal":   {custom("custom-a", "http://127.0.0.1:50123/ok"), TargetRules{AllowHTTP: true, Policy: &Policy{Allow: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}}}, "", "204"},
		"longest id":            {custom("custom-"+strings.Repeat("a", 33), "https://example.net/"), TargetRules{}, "example.net", "204"},
		"longest url":           {custom("custom-a", "https://example.net/"+strings.Repeat("a", spec.MaxCustomURLBytes-len("https://example.net/"))), TargetRules{}, "example.net", "204"},
		"longest needle":        {spec.CustomTarget{ID: "custom-a", URL: "https://example.net/", Method: "GET", ExpectStatus: "200", BodyContains: strings.Repeat("n", spec.MaxBodyContainsBytes)}, TargetRules{}, "example.net", "200"},
		"numeric middle label":  {custom("custom-a", "https://123.example.net/"), TargetRules{}, "123.example.net", "204"},
		"hyphenated label":      {custom("custom-a", "https://a-b.example.net/"), TargetRules{}, "a-b.example.net", "204"},
		"example second level":  {custom("custom-a", "https://example.com/"), TargetRules{}, "example.com", "204"},
		"overlapping ranges ok": {spec.CustomTarget{ID: "custom-a", URL: "https://example.net/", Method: "GET", ExpectStatus: "200-299,204"}, TargetRules{}, "example.net", "200-299,204"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := CheckCustomTarget(0, c.target, c.rules)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if got.Host != c.host || got.Expect.String() != c.expect || !got.Custom || got.ID != c.target.ID {
				t.Errorf("got %+v, want host %q expect %q", got, c.host, c.expect)
			}
		})
	}
}

// TestCheckCustomTargetRefuses holds one row per refusal rule. Every row
// must be refused with the stage shown and a message naming the rule.
func TestCheckCustomTargetRefuses(t *testing.T) {
	strict := TargetRules{}
	deny := TargetRules{Policy: &Policy{Deny: []netip.Prefix{netip.MustParsePrefix("203.0.114.0/24"), netip.MustParsePrefix("8.8.8.8/32")}}}
	withStatus := func(status string) spec.CustomTarget {
		return spec.CustomTarget{ID: "custom-a", URL: "https://example.net/", Method: "GET", ExpectStatus: status}
	}
	cases := []struct {
		name   string
		target spec.CustomTarget
		rules  TargetRules
		stage  spec.Stage
		want   string
	}{
		// id
		{"empty id", custom("", "https://example.net/"), strict, spec.StageRequest, "id must match"},
		{"id without prefix", custom("edge", "https://example.net/"), strict, spec.StageRequest, "id must match"},
		{"id prefix only", custom("custom-", "https://example.net/"), strict, spec.StageRequest, "id must match"},
		{"id upper case", custom("custom-Edge", "https://example.net/"), strict, spec.StageRequest, "id must match"},
		{"id too long", custom("custom-"+strings.Repeat("a", 34), "https://example.net/"), strict, spec.StageRequest, "id must match"},
		// url shape
		{"empty url", custom("custom-a", ""), strict, spec.StagePolicy, "url is required"},
		{"url too long", custom("custom-a", "https://example.net/"+strings.Repeat("a", spec.MaxCustomURLBytes)), strict, spec.StagePolicy, "longer than"},
		{"space in url", custom("custom-a", "https://example.net/a b"), strict, spec.StagePolicy, "printable ASCII"},
		{"non-ascii in url", custom("custom-a", "https://bücher.ch/"), strict, spec.StagePolicy, "printable ASCII"},
		{"control byte in url", custom("custom-a", "https://example.net/\x00"), strict, spec.StagePolicy, "printable ASCII"},
		{"fragment", custom("custom-a", "https://example.net/#top"), strict, spec.StagePolicy, "fragment"},
		{"empty fragment", custom("custom-a", "https://example.net/#"), strict, spec.StagePolicy, "fragment"},
		{"unparseable", custom("custom-a", "https://exa%zzmple.net/"), strict, spec.StagePolicy, "does not parse"},
		{"http by default", custom("custom-a", "http://example.net/"), strict, spec.StagePolicy, "must be https"},
		{"ftp", custom("custom-a", "ftp://example.net/"), TargetRules{AllowHTTP: true}, spec.StagePolicy, "must be https or http"},
		{"no scheme", custom("custom-a", "example.net/"), strict, spec.StagePolicy, "must be https"},
		{"opaque", custom("custom-a", "https:example.net"), strict, spec.StagePolicy, "absolute"},
		{"no host", custom("custom-a", "https:///path"), strict, spec.StagePolicy, "absolute"},
		{"credentials", custom("custom-a", "https://user:pass@example.net/"), strict, spec.StagePolicy, "credentials"},
		{"user only", custom("custom-a", "https://user@example.net/"), strict, spec.StagePolicy, "credentials"},
		// port
		{"empty port", custom("custom-a", "https://example.net:/"), strict, spec.StagePolicy, "empty port"},
		{"port zero", custom("custom-a", "https://example.net:0/"), strict, spec.StagePolicy, "port"},
		{"port too high", custom("custom-a", "https://example.net:65536/"), strict, spec.StagePolicy, "port"},
		{"port leading zero", custom("custom-a", "https://example.net:0443/"), strict, spec.StagePolicy, "leading zero"},
		{"low port", custom("custom-a", "https://example.net:22/"), strict, spec.StagePolicy, "port 22 is not allowed"},
		{"port 80 on https", custom("custom-a", "https://example.net:80/"), strict, spec.StagePolicy, "port 80 is not allowed"},
		{"port 443 on http", custom("custom-a", "http://example.net:443/"), TargetRules{AllowHTTP: true}, spec.StagePolicy, "port 443 is not allowed"},
		// address literals
		{"loopback v4", custom("custom-a", "https://127.0.0.1/"), strict, spec.StagePolicy, "loopback"},
		{"private v4", custom("custom-a", "https://10.1.2.3/"), strict, spec.StagePolicy, "private"},
		{"metadata", custom("custom-a", "https://169.254.169.254/"), strict, spec.StagePolicy, "link-local"},
		{"cgnat", custom("custom-a", "https://100.64.0.1/"), strict, spec.StagePolicy, "CGNAT"},
		{"unspecified", custom("custom-a", "https://0.0.0.0/"), strict, spec.StagePolicy, "this network"},
		{"loopback v6", custom("custom-a", "https://[::1]/"), strict, spec.StagePolicy, "loopback"},
		{"ula v6", custom("custom-a", "https://[fd00::1]/"), strict, spec.StagePolicy, "unique local"},
		{"mapped loopback", custom("custom-a", "https://[::ffff:127.0.0.1]/"), strict, spec.StagePolicy, "loopback"},
		{"nat64 private", custom("custom-a", "https://[64:ff9b::a00:1]/"), strict, spec.StagePolicy, "NAT64"},
		{"zoned v6", custom("custom-a", "https://[fe80::1%25eth0]/"), strict, spec.StagePolicy, "refused"},
		{"bad bracket literal", custom("custom-a", "https://[example.net]/"), strict, spec.StagePolicy, "does not parse"},
		{"denied literal", custom("custom-a", "https://8.8.8.8/"), deny, spec.StagePolicy, "denied"},
		{"denied nat64 form", custom("custom-a", "https://[64:ff9b::808:808]/"), deny, spec.StagePolicy, "denied"},
		{"denied mapped form", custom("custom-a", "https://[::ffff:8.8.8.8]/"), deny, spec.StagePolicy, "denied"},
		// host names
		{"localhost", custom("custom-a", "https://localhost/"), strict, spec.StagePolicy, "single-label"},
		{"localhost subdomain", custom("custom-a", "https://api.localhost/"), strict, spec.StagePolicy, "special-use"},
		{"single label", custom("custom-a", "https://intranet/"), strict, spec.StagePolicy, "single-label"},
		{"trailing dot", custom("custom-a", "https://example.net./"), strict, spec.StagePolicy, "dot"},
		{"empty label", custom("custom-a", "https://a..example.net/"), strict, spec.StagePolicy, "label"},
		{"label leading hyphen", custom("custom-a", "https://-a.example.net/"), strict, spec.StagePolicy, "label"},
		{"label trailing hyphen", custom("custom-a", "https://a-.example.net/"), strict, spec.StagePolicy, "label"},
		{"underscore", custom("custom-a", "https://a_b.example.net/"), strict, spec.StagePolicy, "label"},
		{"label too long", custom("custom-a", "https://"+strings.Repeat("a", 64)+".example.net/"), strict, spec.StagePolicy, "label"},
		{"name too long", custom("custom-a", "https://"+strings.Repeat("a.", 127)+"net/"), strict, spec.StagePolicy, "253"},
		{"short v4 form", custom("custom-a", "https://127.1/"), strict, spec.StagePolicy, "numeric"},
		{"decimal v4 form", custom("custom-a", "https://2130706433/"), strict, spec.StagePolicy, "single-label"},
		{"dotted decimal tail", custom("custom-a", "https://foo.2130706433/"), strict, spec.StagePolicy, "numeric"},
		{"hex v4 form", custom("custom-a", "https://0x7f.0x1/"), strict, spec.StagePolicy, "numeric"},
		{"local suffix", custom("custom-a", "https://printer.local/"), strict, spec.StagePolicy, "special-use"},
		{"internal suffix", custom("custom-a", "https://metadata.google.internal/"), strict, spec.StagePolicy, "special-use"},
		{"test suffix", custom("custom-a", "https://lab.test/"), strict, spec.StagePolicy, "special-use"},
		{"onion", custom("custom-a", "https://abc.onion/"), strict, spec.StagePolicy, "special-use"},
		{"reverse zone", custom("custom-a", "https://1.0.0.127.in-addr.arpa/"), strict, spec.StagePolicy, "special-use"},
		{"home arpa", custom("custom-a", "https://nas.home.arpa/"), strict, spec.StagePolicy, "special-use"},
		{"lan suffix", custom("custom-a", "https://router.lan/"), strict, spec.StagePolicy, "special-use"},
		// method
		{"empty method", spec.CustomTarget{ID: "custom-a", URL: "https://example.net/", ExpectStatus: "204"}, strict, spec.StagePolicy, "method must be GET or HEAD"},
		{"post", spec.CustomTarget{ID: "custom-a", URL: "https://example.net/", Method: "POST", ExpectStatus: "204"}, strict, spec.StagePolicy, "method must be GET or HEAD"},
		{"lower case get", spec.CustomTarget{ID: "custom-a", URL: "https://example.net/", Method: "get", ExpectStatus: "204"}, strict, spec.StagePolicy, "method must be GET or HEAD"},
		// expected status
		{"no status", withStatus(""), strict, spec.StagePolicy, "expect_status is required"},
		{"status 99", withStatus("99"), strict, spec.StagePolicy, "three-digit"},
		{"status 600", withStatus("600"), strict, spec.StagePolicy, "100 to 599"},
		{"status 099", withStatus("099"), strict, spec.StagePolicy, "100 to 599"},
		{"backwards range", withStatus("299-200"), strict, spec.StagePolicy, "backwards"},
		{"spaces", withStatus("200, 301"), strict, spec.StagePolicy, "three-digit"},
		{"trailing comma", withStatus("200,"), strict, spec.StagePolicy, "three-digit"},
		{"open range", withStatus("200-"), strict, spec.StagePolicy, "three-digit"},
		{"double range", withStatus("200-250-299"), strict, spec.StagePolicy, "three-digit"},
		{"word", withStatus("ok"), strict, spec.StagePolicy, "three-digit"},
		{"too many items", withStatus(strings.TrimSuffix(strings.Repeat("200,", 17), ",")), strict, spec.StagePolicy, "at most 16"},
		{"status too long", withStatus(strings.Repeat("2", 129)), strict, spec.StagePolicy, "longer than"},
		// body needle
		{"needle too long", spec.CustomTarget{ID: "custom-a", URL: "https://example.net/", Method: "GET", ExpectStatus: "200", BodyContains: strings.Repeat("n", spec.MaxBodyContainsBytes+1)}, strict, spec.StagePolicy, "longer than"},
		{"needle invalid utf8", spec.CustomTarget{ID: "custom-a", URL: "https://example.net/", Method: "GET", ExpectStatus: "200", BodyContains: "\xff\xfe"}, strict, spec.StagePolicy, "UTF-8"},
		{"needle control", spec.CustomTarget{ID: "custom-a", URL: "https://example.net/", Method: "GET", ExpectStatus: "200", BodyContains: "a\nb"}, strict, spec.StagePolicy, "control"},
		{"needle with head", spec.CustomTarget{ID: "custom-a", URL: "https://example.net/", Method: "HEAD", ExpectStatus: "200", BodyContains: "ok"}, strict, spec.StagePolicy, "HEAD"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := CheckCustomTarget(3, c.target, c.rules)
			var re *spec.RequestError
			if !errors.As(err, &re) {
				t.Fatalf("got %v, want a refusal", err)
			}
			if re.Stage != c.stage || !strings.Contains(re.Message, c.want) {
				t.Errorf("got %s %q, want %s containing %q", re.Stage, re.Message, c.stage, c.want)
			}
			if !strings.HasPrefix(re.Message, "custom_targets[3]") {
				t.Errorf("message %q does not name the custom target", re.Message)
			}
		})
	}
}

func TestParseWithCustomTargets(t *testing.T) {
	ob := json.RawMessage(`{"type":"trojan","tag":"exit","server":"1.1.1.1","server_port":443,"password":"p"}`)
	base := func() *spec.Request {
		return &spec.Request{Outbounds: []json.RawMessage{ob}}
	}

	// Old servers send ids only; nothing changes for them.
	req := base()
	req.Targets = []string{"cloudflare-204", "gstatic-204", "cloudflare-204"}
	p, err := Parse(req, spec.DefaultTargets(), TargetRules{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Targets) != 2 || p.Targets[0].ID != "cloudflare-204" || p.Targets[0].Custom || p.Targets[0].Method != "GET" || p.Targets[0].Expect.String() != "204" {
		t.Errorf("built-in targets: %+v", p.Targets)
	}

	// Custom targets are measured where targets names them.
	req = base()
	req.Targets = []string{"custom-edge", "gstatic-204"}
	req.CustomTargets = []spec.CustomTarget{{ID: "custom-edge", URL: "https://edge.example.net:8443/health", Method: "HEAD", ExpectStatus: "200-299"}}
	p, err = Parse(req, spec.DefaultTargets(), TargetRules{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Targets) != 2 || !p.Targets[0].Custom || p.Targets[0].Host != "edge.example.net" || p.Targets[1].ID != "gstatic-204" {
		t.Errorf("mixed targets: %+v", p.Targets)
	}

	refusals := map[string]struct {
		mutate func(*spec.Request)
		stage  spec.Stage
		want   string
	}{
		"unknown custom id": {func(r *spec.Request) { r.Targets = []string{"custom-nope"} }, spec.StagePolicy, "not in the configured list"},
		"custom not named": {func(r *spec.Request) {
			r.Targets = []string{"gstatic-204"}
			r.CustomTargets = []spec.CustomTarget{custom("custom-edge", "https://example.net/")}
		}, spec.StageRequest, "not named in targets"},
		"custom with no targets": {func(r *spec.Request) {
			r.CustomTargets = []spec.CustomTarget{custom("custom-edge", "https://example.net/")}
		}, spec.StageRequest, "not named in targets"},
		"duplicate custom id": {func(r *spec.Request) {
			r.Targets = []string{"custom-edge"}
			r.CustomTargets = []spec.CustomTarget{custom("custom-edge", "https://example.net/"), custom("custom-edge", "https://example.org/")}
		}, spec.StageRequest, "duplicate"},
		"custom id names a configured target": {func(r *spec.Request) {
			r.Targets = []string{"custom-clash"}
			r.CustomTargets = []spec.CustomTarget{custom("custom-clash", "https://example.net/")}
		}, spec.StagePolicy, "configured target"},
		"bad custom target": {func(r *spec.Request) {
			r.Targets = []string{"custom-edge"}
			r.CustomTargets = []spec.CustomTarget{custom("custom-edge", "https://10.0.0.1/")}
		}, spec.StagePolicy, "private"},
		"too many custom targets": {func(r *spec.Request) {
			for i := range spec.MaxTargetsPerRun + 1 {
				id := "custom-t" + itoa(i)
				r.Targets = append(r.Targets, id)
				r.CustomTargets = append(r.CustomTargets, custom(id, "https://example.net/"))
			}
		}, spec.StagePolicy, "at most 16 custom targets"},
		"too many targets in all": {func(r *spec.Request) {
			r.Targets = []string{"gstatic-204"}
			for i := range spec.MaxTargetsPerRun {
				id := "custom-t" + itoa(i)
				r.Targets = append(r.Targets, id)
				r.CustomTargets = append(r.CustomTargets, custom(id, "https://example.net/"))
			}
		}, spec.StagePolicy, "at most 16 targets"},
	}
	clash := append(spec.DefaultTargets(), spec.Target{ID: "custom-clash", URL: "https://example.net/", Expect: 204})
	for name, c := range refusals {
		t.Run(name, func(t *testing.T) {
			req := base()
			c.mutate(req)
			_, err := Parse(req, clash, TargetRules{})
			var re *spec.RequestError
			if !errors.As(err, &re) || re.Stage != c.stage || !strings.Contains(re.Message, c.want) {
				t.Errorf("got %v, want %s containing %q", err, c.stage, c.want)
			}
		})
	}
}

func itoa(i int) string {
	return string(rune('a'+i/26)) + string(rune('a'+i%26))
}
