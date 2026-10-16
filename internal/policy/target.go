package policy

import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/LatticeNet/lattice-probe/internal/spec"
)

// Custom targets are URLs the operator saved in lattice-server. The server
// sends their definitions with a request, and nothing here trusts that it
// checked them: every definition passes the same rules before the probe
// fetches anything, whoever sent it.
//
// A target is fetched through the outbound under test, with the host name
// left for the far end to resolve, so the connection to a target starts at
// the proxy server, not at the probe. The rules keep a definition to a
// public HTTPS endpoint: no credentials or fragments, the scheme's own port
// or a high one, no address literal outside global unicast or inside the
// probe's deny prefixes, and no name that only means something on a local
// network. Names are also resolved on the probe before the run
// (engine.checkTargetHosts) and refused when any address they give is
// refused here. That is a hint, not a guarantee: the proxy resolves the
// name itself and may get another answer.

// TargetRules are the deployment settings custom targets are checked
// against. The zero value is the production default.
type TargetRules struct {
	// Policy judges address literals and the addresses a name resolves to
	// on the probe. Nil refuses every address that is not global unicast.
	Policy *Policy
	// AllowHTTP permits http:// custom targets, for a lab. Production
	// leaves it off (LATTICE_PROBE_ALLOW_HTTP_TARGETS).
	AllowHTTP bool
}

// Target is one target of a plan: a built-in one, or a custom one that
// passed CheckCustomTarget.
type Target struct {
	ID           string
	URL          string
	Method       string // GET or HEAD
	Expect       spec.StatusSet
	BodyContains string
	Custom       bool
	// Host is the host name of a custom target, for the resolution hint;
	// empty for an address literal and for a built-in target.
	Host string
}

func builtinTarget(t spec.Target) Target {
	return Target{ID: t.ID, URL: t.URL, Method: "GET", Expect: spec.Exactly(t.Expect)}
}

// minHighPort is the lowest explicit port a custom target may name besides
// its scheme's own. Ports below it belong to well-known services (SSH, SMTP,
// DNS and the like) that no HTTPS health endpoint needs.
const minHighPort = 1024

var customTargetID = regexp.MustCompile(`^` + regexp.QuoteMeta(spec.CustomTargetPrefix) + `[a-z0-9-]{1,33}$`)

// specialUseSuffixes are names that resolve only on a local network or
// never at all: RFC 6761 and 6762 special-use names, RFC 9476's alt, the
// arpa zone (reverse lookups and home.arpa), ICANN's reserved internal, and
// the private suffixes routers and corporate networks hand out.
var specialUseSuffixes = []string{
	"localhost", "local", "internal", "test", "invalid", "example", "onion", "alt", "arpa",
	"lan", "home", "corp", "intranet", "localdomain",
}

// CheckCustomTarget validates the custom target at index i of a request and
// returns it as a plan target. Errors are *spec.RequestError naming the
// target; none quotes the URL beyond its host.
func CheckCustomTarget(i int, ct spec.CustomTarget, rules TargetRules) (Target, error) {
	if !customTargetID.MatchString(ct.ID) {
		return Target{}, spec.Malformed(fmt.Sprintf("custom_targets[%d]: id must match ^%s[a-z0-9-]{1,33}$", i, spec.CustomTargetPrefix))
	}
	where := fmt.Sprintf("custom_targets[%d] (%s)", i, ct.ID)
	host, err := checkTargetURL(ct.URL, rules)
	if err != nil {
		return Target{}, spec.Refuse(where + ": " + err.Error())
	}
	if ct.Method != "GET" && ct.Method != "HEAD" {
		return Target{}, spec.Refuse(where + ": method must be GET or HEAD")
	}
	expect, err := spec.ParseStatusSet(ct.ExpectStatus)
	if err != nil {
		return Target{}, spec.Refuse(where + ": " + err.Error())
	}
	if err := checkNeedle(ct.BodyContains, ct.Method); err != nil {
		return Target{}, spec.Refuse(where + ": " + err.Error())
	}
	return Target{
		ID: ct.ID, URL: ct.URL, Method: ct.Method, Expect: expect,
		BodyContains: ct.BodyContains, Custom: true, Host: host,
	}, nil
}

// checkTargetURL applies the URL rules and returns the host name to
// resolve, or "" for an address literal.
func checkTargetURL(raw string, rules TargetRules) (string, error) {
	if raw == "" {
		return "", fmt.Errorf("url is required")
	}
	if len(raw) > spec.MaxCustomURLBytes {
		return "", fmt.Errorf("url is longer than %d bytes", spec.MaxCustomURLBytes)
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] <= ' ' || raw[i] >= 0x7f {
			return "", fmt.Errorf("url must be printable ASCII without spaces; percent-encode anything else")
		}
	}
	if strings.Contains(raw, "#") {
		return "", fmt.Errorf("url must not carry a fragment")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("url does not parse")
	}
	defaultPort := 443
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && rules.AllowHTTP:
		defaultPort = 80
	case rules.AllowHTTP:
		return "", fmt.Errorf("url must be https or http")
	default:
		return "", fmt.Errorf("url must be https")
	}
	if u.Opaque != "" || u.Host == "" {
		return "", fmt.Errorf("url must be absolute, with a host")
	}
	if u.User != nil || strings.Contains(u.Host, "@") {
		return "", fmt.Errorf("url must not carry credentials")
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", fmt.Errorf("url has an empty port")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		switch {
		case err != nil || n < 1 || n > 65535:
			return "", fmt.Errorf("url port must be a number from 1 to 65535")
		case len(port) > 1 && port[0] == '0':
			return "", fmt.Errorf("url port must not have a leading zero")
		case n != defaultPort && n < minHighPort:
			return "", fmt.Errorf("port %d is not allowed; a custom target uses its scheme's port (%d) or one from %d to 65535", n, defaultPort, minHighPort)
		}
	}
	hostname := u.Hostname()
	if addr, err := netip.ParseAddr(hostname); err == nil {
		if r := rules.Policy.Check(addr); r != nil {
			return "", r
		}
		return "", nil
	}
	hostname = strings.ToLower(hostname)
	if err := checkHostName(hostname); err != nil {
		return "", err
	}
	return hostname, nil
}

// checkHostName accepts a fully qualified ASCII DNS name that is not local
// only and cannot be read as an address by a lenient resolver.
func checkHostName(h string) error {
	if len(h) > 253 {
		return fmt.Errorf("host name is longer than 253 characters")
	}
	if strings.HasSuffix(h, ".") {
		return fmt.Errorf("host name must not end with a dot")
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return fmt.Errorf("host %s is a single-label name, which resolves only on a local network; use a fully qualified name", safeName(h))
	}
	for _, label := range labels {
		if !validLabel(label) {
			return fmt.Errorf("host %s has an invalid label; labels are 1 to 63 letters, digits and inner hyphens", safeName(h))
		}
	}
	// inet_aton and URL parsers read "127.1", "0x7f.1" and "2130706433" as
	// IPv4 addresses whenever the last label is numeric; no real TLD is.
	last := labels[len(labels)-1]
	if strings.Trim(last, "0123456789") == "" || strings.HasPrefix(last, "0x") {
		return fmt.Errorf("host %s ends in a numeric label, which some resolvers read as an IPv4 address; write the address in dotted form instead", safeName(h))
	}
	for _, suffix := range specialUseSuffixes {
		if h == suffix || strings.HasSuffix(h, "."+suffix) {
			return fmt.Errorf("host %s is under .%s, a special-use or local-only name", safeName(h), suffix)
		}
	}
	return nil
}

func validLabel(label string) bool {
	if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

func checkNeedle(needle, method string) error {
	if needle == "" {
		return nil
	}
	if len(needle) > spec.MaxBodyContainsBytes {
		return fmt.Errorf("body_contains is longer than %d bytes", spec.MaxBodyContainsBytes)
	}
	if !utf8.ValidString(needle) {
		return fmt.Errorf("body_contains is not valid UTF-8")
	}
	if strings.ContainsFunc(needle, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("body_contains must not hold control characters")
	}
	if method == "HEAD" {
		return fmt.Errorf("body_contains needs GET; a HEAD answer has no body")
	}
	return nil
}

// pickTargets resolves the ids a request names against the configured
// targets and the request's custom targets, in request order without
// duplicates. An empty list measures the first configured target.
func pickTargets(req *spec.Request, configured []spec.Target, rules TargetRules) ([]Target, error) {
	if len(req.CustomTargets) > spec.MaxTargetsPerRun {
		return nil, spec.Refuse(fmt.Sprintf("at most %d custom targets per request, got %d", spec.MaxTargetsPerRun, len(req.CustomTargets)))
	}
	byID := make(map[string]Target, len(configured)+len(req.CustomTargets))
	for _, t := range configured {
		byID[t.ID] = builtinTarget(t)
	}
	custom := make(map[string]bool, len(req.CustomTargets))
	for i, ct := range req.CustomTargets {
		if custom[ct.ID] {
			return nil, spec.Malformed(fmt.Sprintf("custom_targets[%d]: duplicate id %q", i, safeName(ct.ID)))
		}
		if _, clash := byID[ct.ID]; clash {
			return nil, spec.Refuse(fmt.Sprintf("custom_targets[%d]: id %q is a configured target of this probe", i, safeName(ct.ID)))
		}
		t, err := CheckCustomTarget(i, ct, rules)
		if err != nil {
			return nil, err
		}
		custom[ct.ID] = true
		byID[ct.ID] = t
	}
	if len(req.Targets) == 0 {
		if len(req.CustomTargets) > 0 {
			return nil, spec.Malformed(fmt.Sprintf("custom_targets[0] (%s) is not named in targets", safeName(req.CustomTargets[0].ID)))
		}
		if len(configured) == 0 {
			return nil, spec.Refuse("no targets are configured")
		}
		return []Target{builtinTarget(configured[0])}, nil
	}
	out := make([]Target, 0, len(req.Targets))
	seen := make(map[string]bool, len(req.Targets))
	for _, id := range req.Targets {
		t, ok := byID[id]
		if !ok {
			return nil, spec.Refuse(fmt.Sprintf("target %q is not in the configured list; GET /v1/targets lists the ids", safeName(id)))
		}
		if !seen[id] {
			seen[id] = true
			out = append(out, t)
		}
	}
	if len(out) > spec.MaxTargetsPerRun {
		return nil, spec.Refuse(fmt.Sprintf("at most %d targets per request, got %d", spec.MaxTargetsPerRun, len(out)))
	}
	for i, ct := range req.CustomTargets {
		if !seen[ct.ID] {
			return nil, spec.Malformed(fmt.Sprintf("custom_targets[%d] (%s) is not named in targets", i, safeName(ct.ID)))
		}
	}
	return out, nil
}
