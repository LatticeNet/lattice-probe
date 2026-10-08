package measure

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/spec"

	N "github.com/sagernet/sing/common/network"
)

// maxBody bounds what a delay sample reads from a target; anything longer
// is cut and the connection is not reused.
const maxBody = 1 << 20

// Sample is one cold request on a new proxied connection and one warm
// request on the same connection.
type Sample struct {
	Cold     time.Duration // dial start to first response byte
	Warm     time.Duration // second request start to first response byte
	WarmOK   bool          // the warm request reused the connection and got the expected status
	Status   int           // status of the cold request, 0 when no response arrived
	Err      error
	TimedOut bool
}

// OK reports whether the cold request answered with the expected status.
func (s Sample) OK(expect int) bool { return s.Err == nil && s.Status == expect }

// HTTPSample fetches target twice through d: once on a new proxied
// connection (cold, timed with httptrace from the start of the dial to the
// first response byte, so it includes the proxy handshake) and once more on
// the same connection (warm). ctx bounds the whole sample.
func HTTPSample(ctx context.Context, d N.Dialer, target string, expect int, opt Options) Sample {
	var s Sample
	var dialStart atomic.Int64
	base := time.Now()
	tr := transport(d, opt, func() { dialStart.CompareAndSwap(0, int64(time.Since(base))) })
	defer tr.CloseIdleConnections()
	c := client(tr)

	get := func() (status int, firstByte time.Duration, reused bool, err error) {
		var first atomic.Int64
		var wasReused atomic.Bool
		trace := &httptrace.ClientTrace{
			GotConn:              func(i httptrace.GotConnInfo) { wasReused.Store(i.Reused) },
			GotFirstResponseByte: func() { first.CompareAndSwap(0, int64(time.Since(base))) },
		}
		req, err := newRequest(httptrace.WithClientTrace(ctx, trace), target, opt)
		if err != nil {
			return 0, 0, false, err
		}
		resp, err := c.Do(req)
		if err != nil {
			return 0, 0, false, err
		}
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBody))
		resp.Body.Close()
		return resp.StatusCode, time.Duration(first.Load()), wasReused.Load(), err
	}

	status, firstByte, _, err := get()
	s.Status = status
	if err != nil {
		s.Err, s.TimedOut = err, IsTimeout(err) || ctx.Err() != nil
		return s
	}
	s.Cold = firstByte - time.Duration(dialStart.Load())
	if status != expect {
		s.Err = fmt.Errorf("unexpected status %d (want %d)", status, expect)
		return s
	}
	warmStart := time.Since(base)
	status, firstByte, reused, err := get()
	if err == nil && reused && status == expect {
		s.Warm = firstByte - warmStart
		s.WarmOK = true
	}
	return s
}

// Exit fetches a Cloudflare-style trace through d and returns the exit
// address and location it reports.
func Exit(ctx context.Context, d N.Dialer, traceURL string, opt Options) (*spec.Exit, error) {
	tr := transport(d, opt, nil)
	defer tr.CloseIdleConnections()
	req, err := newRequest(ctx, traceURL, opt)
	if err != nil {
		return nil, err
	}
	resp, err := client(tr).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trace answered %d", resp.StatusCode)
	}
	exit := &spec.Exit{}
	sc := bufio.NewScanner(io.LimitReader(resp.Body, 16<<10))
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		switch k {
		case "ip":
			exit.IP = v
		case "loc":
			exit.Loc = v
		case "colo":
			exit.Colo = v
		}
	}
	if exit.IP == "" {
		return nil, errors.New("trace answer carries no ip")
	}
	return exit, nil
}

// Download fetches url through d and times the body from the first
// response byte to the end, so the handshake does not count against the
// rate. A download cut by ctx still reports what arrived.
func Download(ctx context.Context, d N.Dialer, url string, opt Options) (*spec.Throughput, error) {
	tr := transport(d, opt, nil)
	defer tr.CloseIdleConnections()
	var first atomic.Int64
	base := time.Now()
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() { first.CompareAndSwap(0, int64(time.Since(base))) },
	}
	req, err := newRequest(httptrace.WithClientTrace(ctx, trace), url, opt)
	if err != nil {
		return nil, err
	}
	resp, err := client(tr).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download answered %d", resp.StatusCode)
	}
	n, copyErr := io.Copy(io.Discard, resp.Body)
	elapsed := time.Since(base) - time.Duration(first.Load())
	if n == 0 {
		if copyErr == nil {
			copyErr = errors.New("download returned no bytes")
		}
		return nil, copyErr
	}
	seconds := elapsed.Seconds()
	out := &spec.Throughput{Bytes: n, Seconds: roundTo(seconds, 3)}
	if seconds > 0 {
		out.Mbps = roundTo(float64(n)*8/seconds/1e6, 1)
	}
	return out, nil
}

func roundTo(x float64, places int) float64 {
	p := 1.0
	for range places {
		p *= 10
	}
	return float64(int64(x*p+0.5)) / p
}
