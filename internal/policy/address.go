// Package policy decides what a probe request may do before and while it
// touches the network: which outbound types and fields are allowed, how
// outbounds may chain, and which addresses may ever be dialled.
package policy

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
)

// Resolver looks up the addresses of a host name. *net.Resolver satisfies
// it; tests substitute their own.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// Policy holds the address rules. The zero value refuses every address that
// is not global unicast.
type Policy struct {
	// Allow lists prefixes the operator explicitly permits even though they
	// fall in a refused class, for example a lab network. Empty by default.
	// It never permits unspecified or multicast addresses.
	Allow []netip.Prefix
}

// Refusal says why an address may not be dialled.
type Refusal struct {
	Host     string // the name that resolved to Addr; empty for a literal
	Addr     netip.Addr
	Reason   string
	DialTime bool // refused by the dialer itself, after any earlier check
}

func (r *Refusal) Error() string {
	var b strings.Builder
	b.WriteString("address refused: ")
	if r.Host != "" {
		b.WriteString(r.Host)
		b.WriteString(" resolves to ")
	}
	b.WriteString(r.Addr.String())
	b.WriteString(", which is ")
	b.WriteString(r.Reason)
	if r.DialTime {
		b.WriteString(" (refused at dial time)")
	}
	return b.String()
}

type class struct {
	prefix netip.Prefix
	reason string
}

// refused lists the special-purpose ranges a probe never dials. It is the
// IANA special-purpose registry minus what is globally reachable, plus
// 198.18.0.0/15, the range most clients use for fake-ip.
var refused = func() []class {
	table := []struct{ prefix, reason string }{
		{"0.0.0.0/8", "in 0.0.0.0/8 (this network)"},
		{"10.0.0.0/8", "private"},
		{"100.64.0.0/10", "shared address space (CGNAT)"},
		{"127.0.0.0/8", "loopback"},
		{"169.254.0.0/16", "link-local"},
		{"172.16.0.0/12", "private"},
		{"192.0.0.0/24", "reserved for IETF protocol assignments"},
		{"192.0.2.0/24", "reserved for documentation"},
		{"192.88.99.0/24", "the deprecated 6to4 relay anycast range"},
		{"192.168.0.0/16", "private"},
		{"198.18.0.0/15", "reserved for benchmarking (and commonly fake-ip)"},
		{"198.51.100.0/24", "reserved for documentation"},
		{"203.0.113.0/24", "reserved for documentation"},
		{"224.0.0.0/4", "multicast"},
		{"240.0.0.0/4", "reserved"},
		{"::/128", "unspecified"},
		{"::1/128", "loopback"},
		{"64:ff9b:1::/48", "local-use NAT64"},
		{"100::/64", "discard-only"},
		{"2001::/23", "reserved for IETF protocol assignments"},
		{"2001:db8::/32", "reserved for documentation"},
		{"3fff::/20", "reserved for documentation"},
		{"fc00::/7", "private (unique local)"},
		{"fe80::/10", "link-local"},
		{"ff00::/8", "multicast"},
	}
	out := make([]class, len(table))
	for i, c := range table {
		out[i] = class{netip.MustParsePrefix(c.prefix), c.reason}
	}
	return out
}()

var (
	globalUnicast6 = netip.MustParsePrefix("2000::/3")
	nat64          = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour      = netip.MustParsePrefix("2002::/16")
)

// Check returns nil when a may be dialled, or a Refusal saying why not.
func (p *Policy) Check(a netip.Addr) *Refusal {
	reason := classify(a)
	if reason == "" {
		return nil
	}
	a = a.Unmap()
	if p != nil && !a.IsUnspecified() && !a.IsMulticast() {
		for _, allowed := range p.Allow {
			if allowed.Contains(a) {
				return nil
			}
		}
	}
	return &Refusal{Addr: a, Reason: reason}
}

// classify returns why a is refused, or "" when it is global unicast.
func classify(a netip.Addr) string {
	if !a.IsValid() {
		return "not a valid address"
	}
	if a.Zone() != "" {
		return "scoped to an interface"
	}
	a = a.Unmap()
	for _, c := range refused {
		if c.prefix.Contains(a) {
			return c.reason
		}
	}
	if a.Is4() {
		return ""
	}
	// IPv6 forms that embed an IPv4 address are judged by that address.
	if nat64.Contains(a) {
		b := a.As16()
		inner := netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]})
		if r := classify(inner); r != "" {
			return fmt.Sprintf("the NAT64 form of %s, which is %s", inner, r)
		}
		return ""
	}
	if sixToFour.Contains(a) {
		b := a.As16()
		inner := netip.AddrFrom4([4]byte{b[2], b[3], b[4], b[5]})
		if r := classify(inner); r != "" {
			return fmt.Sprintf("the 6to4 form of %s, which is %s", inner, r)
		}
		return ""
	}
	if !globalUnicast6.Contains(a) {
		return "outside the IPv6 global unicast range 2000::/3"
	}
	return ""
}

// ParsePrefixes reads a comma-separated list of CIDR prefixes, such as the
// value of LATTICE_PROBE_ALLOW_PREFIXES. A bare address means a single host.
func ParsePrefixes(list string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, field := range strings.Split(list, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if !strings.Contains(field, "/") {
			a, err := netip.ParseAddr(field)
			if err != nil {
				return nil, fmt.Errorf("allow prefix %q: %w", field, err)
			}
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			continue
		}
		p, err := netip.ParsePrefix(field)
		if err != nil {
			return nil, fmt.Errorf("allow prefix %q: %w", field, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}
