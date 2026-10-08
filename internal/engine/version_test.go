package engine

import (
	"os"
	"regexp"
	"testing"
)

// TestPinnedCoreVersionMatchesGoMod keeps the fallback version honest: a
// sing-box bump in go.mod that forgets the constant fails here.
func TestPinnedCoreVersionMatchesGoMod(t *testing.T) {
	data, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^\s*github\.com/sagernet/sing-box v(\S+)`).FindSubmatch(data)
	if m == nil {
		t.Fatal("go.mod does not require github.com/sagernet/sing-box")
	}
	if got := string(m[1]); got != pinnedCoreVersion {
		t.Fatalf("go.mod requires sing-box %s but pinnedCoreVersion is %s", got, pinnedCoreVersion)
	}
}
