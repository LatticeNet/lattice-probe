package measure

import (
	"bufio"
	"bytes"
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

// Check is what one target asks of its answer.
type Check struct {
	URL    string
	Method string // GET or HEAD
	Expect spec.StatusSet
	// BodyContains, when set, must appear in the first spec.BodyMatchWindow
	// bytes of the body. Only whether it did is kept.
	BodyContains string
}

// Sample is one cold request on a new proxied connection and one warm
// request on the same connection.
type Sample struct {
	Cold     time.Duration // dial start to first response byte
	Warm     time.Duration // second request start to first response byte
	WarmOK   bool          // the warm request reused the connection and passed the check
	Status   int           // status of the cold request, 0 when no response arrived
	Err      error
	TimedOut bool
	// BodyRead is true when the check has a needle and the cold body was
	// read; BodyFound says whether the needle was in it, whatever the status.
	BodyRead  bool
	BodyFound bool
}

// OK reports whether the cold request passed the check.
func (s Sample) OK() bool { return s.Err == nil && s.Status != 0 }

// HTTPSample fetches the target twice through d: once on a new proxied
// connection (cold, timed with httptrace from the start of the dial to the
// first response byte, so it includes the proxy handshake) and once more on
// the same connection (warm). ctx bounds the whole sample.
func HTTPSample(ctx context.Context, d N.Dialer, chk Check, opt Options) Sample {
	var s Sample
	var dialStart atomic.Int64
	base := time.Now()
	tr := transport(d, opt, func() { dialStart.CompareAndSwap(0, int64(time.Since(base))) })
	defer tr.CloseIdleConnections()
	c := client(tr)

	get := func() (status int, firstByte time.Duration, reused, found bool, err error) {
		var first atomic.Int64
		var wasReused atomic.Bool
		trace := &httptrace.ClientTrace{
			GotConn:              func(i httptrace.GotConnInfo) { wasReused.Store(i.Reused) },
			GotFirstResponseByte: func() { first.CompareAndSwap(0, int64(time.Since(base))) },
		}
		req, err := newRequest(httptrace.WithClientTrace(ctx, trace), chk.Method, chk.URL, opt)
		if err != nil {
			return 0, 0, false, false, err
		}
		resp, err := c.Do(req)
		if err != nil {
			return 0, 0, false, false, err
		}
		found, err = readBody(resp.Body, chk.BodyContains)
		resp.Body.Close()
		return resp.StatusCode, time.Duration(first.Load()), wasReused.Load(), found, err
	}
	passes := func(status int, found bool) bool {
		return chk.Expect.Contains(status) && (chk.BodyContains == "" || found)
	}

	status, firstByte, _, found, err := get()
	s.Status = status
	if err != nil {
		s.Err, s.TimedOut = err, IsTimeout(err) || ctx.Err() != nil
		return s
	}
	s.Cold = firstByte - time.Duration(dialStart.Load())
	if chk.BodyContains != "" {
		s.BodyRead, s.BodyFound = true, found
	}
	if !chk.Expect.Contains(status) {
		s.Err = fmt.Errorf("unexpected status %d (want %s)", status, chk.Expect)
		return s
	}
	if !passes(status, found) {
		s.Err = fmt.Errorf("status %d, but the first %d KiB of the body did not contain the expected text", status, spec.BodyMatchWindow>>10)
		return s
	}
	warmStart := time.Since(base)
	status, firstByte, reused, found, err := get()
	if err == nil && reused && passes(status, found) {
		s.Warm = firstByte - warmStart
		s.WarmOK = true
	}
	return s
}

// readBody drains a response body up to maxBody and reports whether needle
// appears in its first spec.BodyMatchWindow bytes. Nothing read is kept.
func readBody(body io.Reader, needle string) (bool, error) {
	if needle == "" {
		_, err := io.Copy(io.Discard, io.LimitReader(body, maxBody))
		return false, err
	}
	head := make([]byte, spec.BodyMatchWindow)
	n, err := io.ReadFull(body, head)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return bytes.Contains(head[:n], []byte(needle)), nil
	}
	if err != nil {
		return false, err
	}
	found := bytes.Contains(head[:n], []byte(needle))
	_, err = io.Copy(io.Discard, io.LimitReader(body, maxBody-int64(n)))
	return found, err
}

// Exit fetches a Cloudflare-style trace through d and returns the exit
// address and location it reports.
func Exit(ctx context.Context, d N.Dialer, traceURL string, opt Options) (*spec.Exit, error) {
	tr := transport(d, opt, nil)
	defer tr.CloseIdleConnections()
	req, err := newRequest(ctx, http.MethodGet, traceURL, opt)
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
	req, err := newRequest(httptrace.WithClientTrace(ctx, trace), http.MethodGet, url, opt)
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
