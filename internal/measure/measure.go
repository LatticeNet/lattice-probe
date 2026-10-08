// Package measure times what a user would feel through an outbound. It
// takes any N.Dialer, so it measures the outbound under test without
// knowing which protocol it speaks.
//
// sing-box's urltest.URLTest is deliberately not used: it sends HEAD,
// rounds to whole milliseconds and leaves the dial out for vmess and vless.
package measure

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/spec"

	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Options are the settings shared by every HTTP measurement.
type Options struct {
	// RootCAs verifies target certificates. Nil means the system roots.
	RootCAs   *x509.CertPool
	UserAgent string
}

// MS converts a duration to milliseconds with one decimal.
func MS(d time.Duration) float64 {
	return math.Round(float64(d)/float64(100*time.Microsecond)) / 10
}

// Summarize returns min, median and p90 (nearest rank) of delays already in
// milliseconds. An empty slice gives zeros.
func Summarize(ms []float64) spec.Dist {
	if len(ms) == 0 {
		return spec.Dist{}
	}
	s := append([]float64(nil), ms...)
	sort.Float64s(s)
	rank := func(p float64) float64 {
		i := int(math.Ceil(p*float64(len(s)))) - 1
		return s[max(i, 0)]
	}
	return spec.Dist{Min: s[0], P50: rank(0.50), P90: rank(0.90)}
}

// OneLine flattens an error to one line without the URL wrapper net/http
// adds, cut to a length a result card can show.
func OneLine(err error) string {
	if err == nil {
		return ""
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// IsTimeout reports whether err is a deadline rather than a refusal.
func IsTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// transport builds a single-use HTTP/1.1 transport whose every connection
// goes through d. Setting TLSClientConfig keeps HTTP/2 off, so cold and warm
// delays are comparable across targets.
func transport(d N.Dialer, opt Options, onDial func()) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if onDial != nil {
				onDial()
			}
			conn, err := d.DialContext(ctx, N.NetworkTCP, M.ParseSocksaddr(addr))
			if err != nil {
				return nil, err
			}
			return writeFirst(conn), nil
		},
		TLSClientConfig:     &tls.Config{RootCAs: opt.RootCAs, MinVersion: tls.VersionTLS12},
		DisableCompression:  true,
		MaxIdleConnsPerHost: 1,
		IdleConnTimeout:     30 * time.Second,
	}
}

func client(tr *http.Transport) *http.Client {
	return &http.Client{
		Transport: tr,
		// The first answer is the one compared with the expected status; a
		// captive portal's redirect must not be followed to a 200.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func newRequest(ctx context.Context, target string, opt Options) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	if opt.UserAgent != "" {
		req.Header.Set("User-Agent", opt.UserAgent)
	}
	return req, nil
}
