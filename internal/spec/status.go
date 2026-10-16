package spec

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// StatusRange is an inclusive range of HTTP status codes. A single status
// is a range whose ends are equal.
type StatusRange struct {
	Lo, Hi int
}

// StatusSet is the set of statuses a target may answer with. Its wire form
// is a comma-separated list of statuses and ranges, "204" or
// "200-299,301", with no spaces.
type StatusSet []StatusRange

const (
	maxStatusItems = 16
	// maxStatusText fits 16 ranges of seven characters and their commas.
	maxStatusText = 128
)

// ParseStatusSet reads the wire form of a status set. Every status is a
// three-digit number from 100 to 599, a range's low end is not above its
// high end, and at most 16 items are allowed. Overlapping items are
// accepted; the set is their union.
func ParseStatusSet(text string) (StatusSet, error) {
	if text == "" {
		return nil, errors.New("expect_status is required, for example 204 or 200-299,301")
	}
	if len(text) > maxStatusText {
		return nil, fmt.Errorf("expect_status is longer than %d characters", maxStatusText)
	}
	items := strings.Split(text, ",")
	if len(items) > maxStatusItems {
		return nil, fmt.Errorf("expect_status lists %d items; at most %d are allowed", len(items), maxStatusItems)
	}
	set := make(StatusSet, 0, len(items))
	for _, item := range items {
		lo, hi, isRange := strings.Cut(item, "-")
		low, err := parseStatus(lo)
		if err != nil {
			return nil, err
		}
		high := low
		if isRange {
			if high, err = parseStatus(hi); err != nil {
				return nil, err
			}
			if high < low {
				return nil, fmt.Errorf("expect_status range %d-%d runs backwards", low, high)
			}
		}
		set = append(set, StatusRange{Lo: low, Hi: high})
	}
	return set, nil
}

func parseStatus(text string) (int, error) {
	if len(text) != 3 || strings.Trim(text, "0123456789") != "" {
		return 0, fmt.Errorf("expect_status item %q is not a three-digit status; write 204 or 200-299,301", clip(text))
	}
	n, _ := strconv.Atoi(text)
	if n < 100 || n > 599 {
		return 0, fmt.Errorf("expect_status %d is not an HTTP status (100 to 599)", n)
	}
	return n, nil
}

// Exactly is the set holding one status, the form a built-in target uses.
func Exactly(status int) StatusSet { return StatusSet{{Lo: status, Hi: status}} }

// Contains reports whether status is in the set.
func (s StatusSet) Contains(status int) bool {
	for _, r := range s {
		if status >= r.Lo && status <= r.Hi {
			return true
		}
	}
	return false
}

// String is the wire form of the set.
func (s StatusSet) String() string {
	parts := make([]string, len(s))
	for i, r := range s {
		if r.Lo == r.Hi {
			parts[i] = strconv.Itoa(r.Lo)
		} else {
			parts[i] = strconv.Itoa(r.Lo) + "-" + strconv.Itoa(r.Hi)
		}
	}
	return strings.Join(parts, ",")
}

// clip keeps an echoed fragment short and printable.
func clip(s string) string {
	if len(s) > 12 {
		s = s[:12] + "..."
	}
	return strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}
