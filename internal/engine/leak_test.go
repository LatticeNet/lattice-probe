package engine

import (
	"context"
	"encoding/json"
	"runtime"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/spec"
	"github.com/LatticeNet/lattice-probe/internal/testkit"
)

// TestNoLeaksAfter200Runs runs 200 probes across every protocol and every
// way a probe ends (pass, wrong credential, timeout, caller cancel) and
// checks that each one removed its outbounds, then that goroutines and file
// descriptors return to where they started.
func TestNoLeaksAfter200Runs(t *testing.T) {
	if testing.Short() {
		t.Skip("long")
	}
	l := sharedLab(t)
	e := newEngine(t, l, func(c *Config) { c.SampleTimeout = 300 * time.Millisecond })

	host, port := splitHostPort(t, l.Blackhole)
	blackhole := l.Outbound("vless", "", "line")
	blackhole["server"], blackhole["server_port"] = host, port
	rawBlackhole, _ := json.Marshal(blackhole)

	quick := func(raw json.RawMessage) *spec.Request {
		return &spec.Request{Outbounds: []json.RawMessage{raw}, Targets: []string{"lab-204"}, Samples: 1, UDP: true, TimeoutMS: 5000}
	}
	// Warm every code path once so lazily started package state is part of
	// the baseline rather than counted as a leak.
	for _, proto := range testkit.Protocols {
		mustRun(t, e, quick(l.OutboundJSON(proto, "", "line")))
		mustRun(t, e, quick(l.OutboundJSON(proto, "wrong", "line")))
	}
	baseG, baseFD := settle(t, -1, -1)

	ends := map[string]int{}
	for i := range 200 {
		proto := testkit.Protocols[i%len(testkit.Protocols)]
		var stage spec.Stage
		switch {
		case i%40 == 7:
			res := mustRun(t, e, quick(rawBlackhole))
			stage = res.Stage
		case i%40 == 23:
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			res, err := e.Run(ctx, quick(rawBlackhole))
			cancel()
			if err != nil {
				t.Fatalf("run %d: %v", i, err)
			}
			stage = "cancelled-" + res.Stage
		case i%3 == 0:
			stage = mustRun(t, e, quick(l.OutboundJSON(proto, "wrong", "line"))).Stage
		default:
			stage = mustRun(t, e, quick(l.OutboundJSON(proto, "", "line"))).Stage
		}
		ends[string(stage)]++
		if n := e.outboundCount(); n != 1 {
			t.Fatalf("run %d (%s, %s): %d outbounds left, want only direct", i, proto, stage, n)
		}
	}
	t.Logf("ends: %v", ends)
	for _, want := range []string{"ok", "handshake", "timeout", "cancelled-timeout"} {
		if ends[want] == 0 {
			t.Errorf("no run ended in %s; the mix no longer covers every exit path", want)
		}
	}

	g, fd := settle(t, baseG, baseFD)
	t.Logf("goroutines %d -> %d, fds %d -> %d", baseG, g, baseFD, fd)
}

// settle waits for goroutines and file descriptors to drain. Without a
// baseline it returns once the counts stop falling. With one it fails
// unless both come back within a small margin; the lab's own servers share
// the process, so a few may still be closing.
func settle(t *testing.T, baseG, baseFD int) (int, int) {
	t.Helper()
	const margin = 4
	deadline := time.Now().Add(20 * time.Second)
	lastG, steady := -1, 0
	for {
		runtime.GC()
		time.Sleep(200 * time.Millisecond)
		g, fd := runtime.NumGoroutine(), testkit.FDs()
		if baseG < 0 {
			if g == lastG {
				steady++
			} else {
				steady = 0
			}
			lastG = g
			if steady >= 3 || time.Now().After(deadline) {
				return g, fd
			}
			continue
		}
		if g <= baseG+margin && (fd < 0 || fd <= baseFD+margin) {
			return g, fd
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			n := runtime.Stack(buf, true)
			t.Fatalf("leak: goroutines %d -> %d, fds %d -> %d\n%s", baseG, g, baseFD, fd, buf[:n])
		}
	}
}
