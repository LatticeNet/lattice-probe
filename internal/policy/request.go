package policy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/spec"
)

// AllowedTypes are the outbound types a probe may create. Everything else,
// including direct, block, dns, selector and urltest, is refused.
var AllowedTypes = map[string]bool{
	"shadowsocks": true,
	"vmess":       true,
	"vless":       true,
	"trojan":      true,
	"hysteria":    true,
	"hysteria2":   true,
	"tuic":        true,
	"shadowtls":   true,
	"anytls":      true,
	"socks":       true,
	"http":        true,
	"ssh":         true,
}

// QUICTypes run over QUIC, so their server check is a UDP handshake attempt.
var QUICTypes = map[string]bool{
	"hysteria":  true,
	"hysteria2": true,
	"tuic":      true,
}

const maxTagLen = 128

// Outbound is one outbound of a request after the structural checks.
type Outbound struct {
	Index  int
	Type   string
	Tag    string
	Detour string // a tag of the same request, or empty
	Host   string // the server field as written
	Port   uint16
	Raw    map[string]json.RawMessage
}

// Server is host:port of the outbound's server.
func (o Outbound) Server() string {
	return net.JoinHostPort(o.Host, strconv.Itoa(int(o.Port)))
}

// Literal reports the server as an address when it is written as one.
func (o Outbound) Literal() (netip.Addr, bool) {
	a, err := netip.ParseAddr(o.Host)
	return a, err == nil
}

// Plan is a request that passed every check that needs no network.
type Plan struct {
	Outbounds       []Outbound
	Order           []int // creation order: every outbound after its detour
	Test            int   // index of the outbound to measure
	Root            int   // index of the first hop of Test's chain
	Targets         []spec.Target
	Samples         int
	UDP             bool
	Throughput      bool
	ThroughputBytes int64
	Timeout         time.Duration
	Secrets         []string
}

// Types lists the outbound types in request order.
func (p *Plan) Types() []string {
	out := make([]string, len(p.Outbounds))
	for i, o := range p.Outbounds {
		out[i] = o.Type
	}
	return out
}

// Parse validates a request against the shape and policy rules that need
// no network and returns the plan. Errors are *spec.RequestError.
func Parse(req *spec.Request, targets []spec.Target) (*Plan, error) {
	if req.Engine != "" && req.Engine != spec.EngineName {
		return nil, spec.Refuse(fmt.Sprintf("engine %q is not available; this probe runs %s", req.Engine, spec.EngineName))
	}
	if len(req.Outbounds) == 0 {
		return nil, spec.Malformed("outbounds is required: one sing-box outbound object, or several for a chain")
	}
	if len(req.Outbounds) > spec.MaxOutbounds {
		return nil, spec.Refuse(fmt.Sprintf("at most %d outbounds per request, got %d", spec.MaxOutbounds, len(req.Outbounds)))
	}
	p := &Plan{Outbounds: make([]Outbound, len(req.Outbounds))}
	byTag := make(map[string]int, len(req.Outbounds))
	for i, raw := range req.Outbounds {
		ob, err := parseOutbound(i, raw)
		if err != nil {
			return nil, err
		}
		if j, dup := byTag[ob.Tag]; dup {
			return nil, spec.Malformed(fmt.Sprintf("outbounds[%d]: tag %q is already used by outbounds[%d]", i, ob.Tag, j))
		}
		byTag[ob.Tag] = i
		p.Outbounds[i] = ob
		p.Secrets = appendSecrets(p.Secrets, ob.Raw)
	}
	for i, ob := range p.Outbounds {
		if ob.Detour == "" {
			continue
		}
		if ob.Detour == ob.Tag {
			return nil, spec.Refuse(fmt.Sprintf("outbounds[%d]: detour names the outbound itself", i))
		}
		if _, ok := byTag[ob.Detour]; !ok {
			return nil, spec.Refuse(fmt.Sprintf("outbounds[%d]: detour %q is not an outbound of this request; a detour may only name a tag defined in the same request", i, ob.Detour))
		}
	}
	order, err := creationOrder(p.Outbounds, byTag)
	if err != nil {
		return nil, err
	}
	p.Order = order

	switch {
	case req.Test != "":
		i, ok := byTag[req.Test]
		if !ok {
			return nil, spec.Malformed(fmt.Sprintf("test %q does not name an outbound of this request", req.Test))
		}
		p.Test = i
	case len(p.Outbounds) == 1:
		p.Test = 0
	default:
		return nil, spec.Malformed("test is required when the request carries more than one outbound")
	}
	p.Root = p.Test
	for p.Outbounds[p.Root].Detour != "" {
		p.Root = byTag[p.Outbounds[p.Root].Detour]
	}

	if p.Targets, err = pickTargets(req.Targets, targets); err != nil {
		return nil, err
	}
	switch {
	case req.Samples == 0:
		p.Samples = spec.DefaultSamples
	case req.Samples < spec.MinSamples || req.Samples > spec.MaxSamples:
		return nil, spec.Refuse(fmt.Sprintf("samples must be %d to %d, got %d", spec.MinSamples, spec.MaxSamples, req.Samples))
	default:
		p.Samples = req.Samples
	}
	switch {
	case req.TimeoutMS == 0:
		p.Timeout = spec.DefaultTimeoutMS * time.Millisecond
	case req.TimeoutMS < spec.MinTimeoutMS || req.TimeoutMS > spec.MaxTimeoutMS:
		return nil, spec.Refuse(fmt.Sprintf("timeout_ms must be %d to %d, got %d", spec.MinTimeoutMS, spec.MaxTimeoutMS, req.TimeoutMS))
	default:
		p.Timeout = time.Duration(req.TimeoutMS) * time.Millisecond
	}
	switch {
	case req.ThroughputBytes < 0:
		return nil, spec.Refuse(fmt.Sprintf("throughput_bytes must not be negative, got %d", req.ThroughputBytes))
	case req.ThroughputBytes > spec.MaxThroughputBytes:
		return nil, spec.Refuse(fmt.Sprintf("throughput_bytes is capped at %d (25 MB), got %d", spec.MaxThroughputBytes, req.ThroughputBytes))
	case req.ThroughputBytes == 0:
		p.ThroughputBytes = spec.DefaultThroughputBytes
	default:
		p.ThroughputBytes = req.ThroughputBytes
	}
	p.UDP = req.UDP
	p.Throughput = req.Throughput
	return p, nil
}

func parseOutbound(i int, raw json.RawMessage) (Outbound, error) {
	ob := Outbound{Index: i}
	if err := json.Unmarshal(raw, &ob.Raw); err != nil || ob.Raw == nil {
		return ob, spec.Malformed(fmt.Sprintf("outbounds[%d] is not a JSON object", i))
	}
	str := func(key string, required bool) (string, error) {
		v, ok := ob.Raw[key]
		if !ok || string(v) == "null" {
			if required {
				return "", spec.Malformed(fmt.Sprintf("outbounds[%d]: %s is required", i, key))
			}
			return "", nil
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return "", spec.Malformed(fmt.Sprintf("outbounds[%d]: %s must be a string", i, key))
		}
		if required && s == "" {
			return "", spec.Malformed(fmt.Sprintf("outbounds[%d]: %s is required", i, key))
		}
		return s, nil
	}
	var err error
	if ob.Type, err = str("type", true); err != nil {
		return ob, err
	}
	if !AllowedTypes[ob.Type] {
		return ob, spec.Refuse(fmt.Sprintf("outbounds[%d]: type %q is not allowed; allowed types are %s", i, safeName(ob.Type), allowedList()))
	}
	if ob.Tag, err = str("tag", true); err != nil {
		return ob, err
	}
	if len(ob.Tag) > maxTagLen {
		return ob, spec.Malformed(fmt.Sprintf("outbounds[%d]: tag is longer than %d bytes", i, maxTagLen))
	}
	if ob.Detour, err = str("detour", false); err != nil {
		return ob, err
	}
	if ob.Host, err = str("server", true); err != nil {
		return ob, err
	}
	if len(ob.Host) > 253 || strings.ContainsAny(ob.Host, " /\\@?#[]") {
		return ob, spec.Malformed(fmt.Sprintf("outbounds[%d]: server must be a host name or an address", i))
	}
	if ob.Port, err = serverPort(i, ob); err != nil {
		return ob, err
	}
	var tree any
	_ = json.Unmarshal(raw, &tree)
	if path := findPathField(tree, ""); path != "" {
		return ob, spec.Refuse(fmt.Sprintf("outbounds[%d]: %s reads a file on the probe host, which is not allowed; inline the value instead", i, path))
	}
	return ob, nil
}

// serverPort reads server_port, falling back to the first port of
// server_ports for the hysteria protocols, which may omit server_port.
func serverPort(i int, ob Outbound) (uint16, error) {
	if v, ok := ob.Raw["server_port"]; ok && string(v) != "null" {
		var n int
		if err := json.Unmarshal(v, &n); err != nil || n < 1 || n > 65535 {
			return 0, spec.Malformed(fmt.Sprintf("outbounds[%d]: server_port must be a number from 1 to 65535", i))
		}
		return uint16(n), nil
	}
	if v, ok := ob.Raw["server_ports"]; ok && (ob.Type == "hysteria" || ob.Type == "hysteria2") {
		var ranges []string
		if err := json.Unmarshal(v, &ranges); err != nil {
			var one string
			if json.Unmarshal(v, &one) == nil {
				ranges = []string{one}
			}
		}
		if len(ranges) > 0 {
			first, _, _ := strings.Cut(ranges[0], ":")
			if n, err := strconv.Atoi(strings.TrimSpace(first)); err == nil && n >= 1 && n <= 65535 {
				return uint16(n), nil
			}
		}
	}
	return 0, spec.Malformed(fmt.Sprintf("outbounds[%d]: server_port is required", i))
}

// findPathField returns the JSON path of the first field that names a file
// on the probe host (certificate_path, key_path, private_key_path, ...).
func findPathField(v any, at string) string {
	switch t := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			path := k
			if at != "" {
				path = at + "." + k
			}
			if strings.HasSuffix(k, "_path") && carriesValue(t[k]) {
				return path
			}
			if p := findPathField(t[k], path); p != "" {
				return p
			}
		}
	case []any:
		for i, e := range t {
			if p := findPathField(e, fmt.Sprintf("%s[%d]", at, i)); p != "" {
				return p
			}
		}
	}
	return ""
}

func carriesValue(v any) bool {
	switch t := v.(type) {
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	}
	return false
}

func creationOrder(obs []Outbound, byTag map[string]int) ([]int, error) {
	const (
		unseen = iota
		visiting
		done
	)
	state := make([]int, len(obs))
	order := make([]int, 0, len(obs))
	var visit func(i int) error
	visit = func(i int) error {
		switch state[i] {
		case done:
			return nil
		case visiting:
			return spec.Refuse(fmt.Sprintf("outbounds[%d]: detours form a cycle", i))
		}
		state[i] = visiting
		if d := obs[i].Detour; d != "" {
			if err := visit(byTag[d]); err != nil {
				return err
			}
		}
		state[i] = done
		order = append(order, i)
		return nil
	}
	for i := range obs {
		if err := visit(i); err != nil {
			return nil, err
		}
	}
	return order, nil
}

func pickTargets(ids []string, targets []spec.Target) ([]spec.Target, error) {
	if len(targets) == 0 {
		return nil, spec.Refuse("no targets are configured")
	}
	if len(ids) == 0 {
		return targets[:1], nil
	}
	byID := make(map[string]spec.Target, len(targets))
	for _, t := range targets {
		byID[t.ID] = t
	}
	out := make([]spec.Target, 0, len(ids))
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		t, ok := byID[id]
		if !ok {
			return nil, spec.Refuse(fmt.Sprintf("target %q is not in the configured list; GET /v1/targets lists the ids", safeName(id)))
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, t)
		}
	}
	return out, nil
}

func allowedList() string {
	names := make([]string, 0, len(AllowedTypes))
	for t := range AllowedTypes {
		names = append(names, t)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// safeName keeps caller-supplied names short and printable in messages.
func safeName(s string) string {
	if len(s) > 40 {
		s = s[:40] + "..."
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}
