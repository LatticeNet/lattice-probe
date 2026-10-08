package measure

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSummarize(t *testing.T) {
	d := Summarize([]float64{9, 1, 5, 3, 7, 2, 8, 4, 6, 10})
	if d.Min != 1 || d.P50 != 5 || d.P90 != 9 {
		t.Errorf("%+v", d)
	}
	if d := Summarize([]float64{4.2}); d.Min != 4.2 || d.P50 != 4.2 || d.P90 != 4.2 {
		t.Errorf("one sample: %+v", d)
	}
	if d := Summarize(nil); d.Min != 0 || d.P50 != 0 || d.P90 != 0 {
		t.Errorf("no samples: %+v", d)
	}
}

func TestMS(t *testing.T) {
	cases := map[time.Duration]float64{
		1234567 * time.Nanosecond: 1.2,
		1250 * time.Microsecond:   1.3,
		49 * time.Microsecond:     0,
		3 * time.Second:           3000,
	}
	for d, want := range cases {
		if got := MS(d); got != want {
			t.Errorf("MS(%s) = %v, want %v", d, got, want)
		}
	}
}

func TestOneLine(t *testing.T) {
	err := &url.Error{Op: "Get", URL: "https://x/", Err: errors.New("read: connection\nreset by peer")}
	if got := OneLine(err); got != "read: connection reset by peer" {
		t.Errorf("%q", got)
	}
	long := OneLine(fmt.Errorf("%s", strings.Repeat("x", 500)))
	if len(long) != 303 {
		t.Errorf("long error is %d bytes", len(long))
	}
}
