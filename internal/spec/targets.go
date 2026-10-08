package spec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
)

// Target is a URL a probe may fetch through the tested outbound. Requests
// name targets by id; they can never supply a URL of their own.
type Target struct {
	ID     string `json:"id"`
	URL    string `json:"url"`
	Expect int    `json:"expect"`
}

// TargetList is the body of GET /v1/targets and the shape of the file named
// by LATTICE_PROBE_TARGETS_FILE.
type TargetList struct {
	Targets []Target `json:"targets"`
}

const maxTargets = 16

var targetID = regexp.MustCompile(`^[a-z0-9-]{1,40}$`)

// DefaultTargets is the built-in list used when no targets file is set.
func DefaultTargets() []Target {
	return []Target{
		{ID: "gstatic-204", URL: "https://www.gstatic.com/generate_204", Expect: 204},
		{ID: "cloudflare-204", URL: "https://cp.cloudflare.com/generate_204", Expect: 204},
		{ID: "apple-success", URL: "https://www.apple.com/library/test/success.html", Expect: 200},
	}
}

// LoadTargets reads a targets file, or returns the default list when path
// is empty. The file replaces the list; it is not merged with it.
func LoadTargets(path string) ([]Target, error) {
	if path == "" {
		return DefaultTargets(), nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read targets file: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var list TargetList
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("parse targets file %s: %w", path, err)
	}
	if err := ValidateTargets(list.Targets); err != nil {
		return nil, fmt.Errorf("targets file %s: %w", path, err)
	}
	return list.Targets, nil
}

// ValidateTargets enforces the rules for an operator-supplied list: ids
// match ^[a-z0-9-]{1,40}$ and are unique, URLs are https with a host and no
// credentials, and the expected status is a real HTTP status.
func ValidateTargets(targets []Target) error {
	if len(targets) == 0 {
		return fmt.Errorf("the list is empty")
	}
	if len(targets) > maxTargets {
		return fmt.Errorf("at most %d targets are allowed, got %d", maxTargets, len(targets))
	}
	seen := make(map[string]bool, len(targets))
	for i, t := range targets {
		if !targetID.MatchString(t.ID) {
			return fmt.Errorf("targets[%d]: id %q does not match ^[a-z0-9-]{1,40}$", i, t.ID)
		}
		if seen[t.ID] {
			return fmt.Errorf("targets[%d]: duplicate id %q", i, t.ID)
		}
		seen[t.ID] = true
		u, err := url.Parse(t.URL)
		if err != nil {
			return fmt.Errorf("targets[%d] (%s): %w", i, t.ID, err)
		}
		if u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("targets[%d] (%s): url must be https with a host", i, t.ID)
		}
		if u.User != nil {
			return fmt.Errorf("targets[%d] (%s): url must not carry credentials", i, t.ID)
		}
		if t.Expect < 100 || t.Expect > 599 {
			return fmt.Errorf("targets[%d] (%s): expect must be an HTTP status, got %d", i, t.ID, t.Expect)
		}
	}
	return nil
}
