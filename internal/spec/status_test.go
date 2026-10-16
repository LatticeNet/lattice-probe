package spec

import (
	"strings"
	"testing"
)

func TestParseStatusSet(t *testing.T) {
	good := map[string]struct {
		in, out string
		yes, no []int
	}{
		"one":        {"204", "204", []int{204}, []int{200, 205}},
		"range":      {"200-299", "200-299", []int{200, 250, 299}, []int{199, 300}},
		"mixed":      {"200-299,301", "200-299,301", []int{204, 301}, []int{302, 404}},
		"bounds":     {"100-599", "100-599", []int{100, 599}, []int{99, 600}},
		"degenerate": {"204-204", "204", []int{204}, []int{203}},
	}
	for name, c := range good {
		set, err := ParseStatusSet(c.in)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if set.String() != c.out {
			t.Errorf("%s: String() = %q, want %q", name, set.String(), c.out)
		}
		for _, s := range c.yes {
			if !set.Contains(s) {
				t.Errorf("%s: does not contain %d", name, s)
			}
		}
		for _, s := range c.no {
			if set.Contains(s) {
				t.Errorf("%s: contains %d", name, s)
			}
		}
	}
	bad := map[string]string{
		"":                                 "required",
		"99":                               "three-digit",
		"1000":                             "three-digit",
		"600":                              "100 to 599",
		"000":                              "100 to 599",
		"200 ":                             "three-digit",
		" 200":                             "three-digit",
		"200,,301":                         "three-digit",
		"-200":                             "three-digit",
		"299-200":                          "backwards",
		"2xx":                              "three-digit",
		"+200":                             "three-digit",
		"200-299-399":                      "three-digit",
		strings.Repeat("200,", 16) + "200": "at most 16",
	}
	for in, want := range bad {
		if _, err := ParseStatusSet(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want an error containing %q", in, err, want)
		}
	}
	if Exactly(204).String() != "204" || !Exactly(204).Contains(204) {
		t.Error("Exactly(204)")
	}
}
