package policy

import (
	"encoding/json"
	"sort"
	"strings"
)

// secretKey reports whether a field name usually carries a credential.
func secretKey(k string) bool {
	k = strings.ToLower(k)
	if k == "key" || k == "short_id" {
		return true
	}
	for _, part := range []string{"pass", "uuid", "secret", "token", "auth", "psk", "private", "pre_shared"} {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}

// minSecretLen keeps one-letter values from redacting half a message.
const minSecretLen = 4

// appendSecrets collects every string value stored under a credential-like
// key, at any depth, so error text can be scrubbed before it leaves.
func appendSecrets(out []string, raw map[string]json.RawMessage) []string {
	var walk func(v any, secret bool)
	walk = func(v any, secret bool) {
		switch t := v.(type) {
		case map[string]any:
			for k, inner := range t {
				walk(inner, secret || secretKey(k))
			}
		case []any:
			for _, inner := range t {
				walk(inner, secret)
			}
		case string:
			if secret && len(t) >= minSecretLen {
				out = append(out, t)
			}
		}
	}
	for k, v := range raw {
		var inner any
		if json.Unmarshal(v, &inner) == nil {
			walk(inner, secretKey(k))
		}
	}
	return out
}

// Redact replaces every secret value in s with [redacted]. Longer secrets
// go first so a secret that contains a shorter one is removed whole.
func Redact(s string, secrets []string) string {
	if s == "" || len(secrets) == 0 {
		return s
	}
	sorted := append([]string(nil), secrets...)
	sort.Slice(sorted, func(i, j int) bool { return len(sorted[i]) > len(sorted[j]) })
	for _, secret := range sorted {
		s = strings.ReplaceAll(s, secret, "[redacted]")
	}
	return s
}
