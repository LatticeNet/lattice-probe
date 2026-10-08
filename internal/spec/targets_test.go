package spec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultTargetsAreValid(t *testing.T) {
	if err := ValidateTargets(DefaultTargets()); err != nil {
		t.Fatal(err)
	}
}

func TestLoadTargets(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		path := filepath.Join(dir, "targets.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	got, err := LoadTargets(write(`{"targets":[{"id":"edge-1","url":"https://example.net/204","expect":204}]}`))
	if err != nil || len(got) != 1 || got[0].ID != "edge-1" {
		t.Fatalf("%v %v", got, err)
	}
	bad := map[string]string{
		"http url":      `{"targets":[{"id":"a","url":"http://example.net/","expect":204}]}`,
		"bad id":        `{"targets":[{"id":"Upper_Case","url":"https://example.net/","expect":204}]}`,
		"long id":       `{"targets":[{"id":"` + strings.Repeat("a", 41) + `","url":"https://example.net/","expect":204}]}`,
		"duplicate":     `{"targets":[{"id":"a","url":"https://x.net/","expect":204},{"id":"a","url":"https://y.net/","expect":204}]}`,
		"credentials":   `{"targets":[{"id":"a","url":"https://u:p@example.net/","expect":204}]}`,
		"no status":     `{"targets":[{"id":"a","url":"https://example.net/"}]}`,
		"empty":         `{"targets":[]}`,
		"unknown field": `{"targets":[],"extra":1}`,
		"not json":      `targets`,
		"no host":       `{"targets":[{"id":"a","url":"https:///x","expect":204}]}`,
	}
	for name, body := range bad {
		if _, err := LoadTargets(write(body)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if got, err := LoadTargets(""); err != nil || len(got) != 3 {
		t.Errorf("default list: %v %v", got, err)
	}
}
