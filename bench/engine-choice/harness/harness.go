// Package harness is the measurement code shared by both probe programs.
// Engines supply create, dial, remove and urltest; everything that is timed
// or counted lives here so both engines are measured the same way.
package harness

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"os"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type Outbound interface {
	Dial(ctx context.Context, addr string) (net.Conn, error)
	Remove() error
}

type Engine interface {
	Name() string
	Module() string // Go module path, used to read the version from build info
	Notes() map[string]any
	Start() error
	Config(r Resolved) ([]byte, error)
	Create(tag string, cfg []byte) (Outbound, error)
	URLTest(ctx context.Context, ob Outbound, url string) (uint16, error)
}

type Sample struct {
	Proto       string  `json:"proto"`
	Variant     string  `json:"variant,omitempty"`
	OK          bool    `json:"ok"`
	Stage       string  `json:"stage,omitempty"`
	Err         string  `json:"err,omitempty"`
	TimedOut    bool    `json:"timed_out,omitempty"`
	CreateMs    float64 `json:"create_ms"`
	DialMs      float64 `json:"dial_ms"`
	ColdMs      float64 `json:"cold_ms"`
	WarmMs      float64 `json:"warm_ms"`
	RemoveMs    float64 `json:"remove_ms"`
	ToErrorMs   float64 `json:"to_error_ms,omitempty"`
	GetToErrMs  float64 `json:"get_to_error_ms,omitempty"`
	WarmReused  bool    `json:"warm_reused"`
	ColdReused  bool    `json:"cold_reused"`
	StatusCold  int     `json:"status_cold,omitempty"`
	StatusWarm  int     `json:"status_warm,omitempty"`
	RemoveError string  `json:"remove_err,omitempty"`
}

type Dist struct {
	N    int     `json:"n"`
	Min  float64 `json:"min"`
	P50  float64 `json:"p50"`
	P90  float64 `json:"p90"`
	P99  float64 `json:"p99"`
	Max  float64 `json:"max"`
	Mean float64 `json:"mean"`
}

func dist(v []float64) Dist {
	if len(v) == 0 {
		return Dist{}
	}
	s := append([]float64(nil), v...)
	sort.Float64s(s)
	rank := func(p float64) float64 {
		i := int(math.Ceil(p*float64(len(s)))) - 1
		if i < 0 {
			i = 0
		}
		return round3(s[i])
	}
	sum := 0.0
	for _, x := range s {
		sum += x
	}
	return Dist{N: len(s), Min: round3(s[0]), P50: rank(0.50), P90: rank(0.90), P99: rank(0.99), Max: round3(s[len(s)-1]), Mean: round3(sum / float64(len(s)))}
}

func round3(x float64) float64 { return math.Round(x*1000) / 1000 }

func msSince(t time.Time) float64 { return round3(float64(time.Since(t)) / 1e6) }

// stamp is a race-free timestamp written from transport goroutines.
type stamp struct{ ns atomic.Int64 }

func (s *stamp) set(base time.Time) { s.ns.Store(int64(time.Since(base))) }
func (s *stamp) get() int64         { return s.ns.Load() }

func oneLine(err error) string {
	if err == nil {
		return ""
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	s := strings.ReplaceAll(err.Error(), "\n", " | ")
	if len(s) > 400 {
		s = s[:400] + "..."
	}
	return s
}

func isTimeout(err error, elapsed, limit time.Duration) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return elapsed >= limit-50*time.Millisecond
}

// RunTest is one probe: create, cold GET on a new proxied connection,
// warm GET on the same connection, close it, remove the outbound.
func RunTest(e Engine, target string, c Case, tag string, cfg []byte, timeout time.Duration, warm bool) Sample {
	s := Sample{Proto: c.Proto, Variant: c.Variant}
	begin := time.Now()
	ob, err := e.Create(tag, cfg)
	s.CreateMs = msSince(begin)
	if err != nil {
		s.Stage, s.Err, s.ToErrorMs = "create", oneLine(err), msSince(begin)
		return s
	}
	defer func() {
		if ob != nil {
			_ = ob.Remove()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	base := time.Now()
	var dialStart, dialEnd, firstByte stamp
	var dialErr atomic.Value
	var reused atomic.Bool
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			dialStart.set(base)
			conn, err := ob.Dial(ctx, addr)
			dialEnd.set(base)
			if err != nil {
				dialErr.Store(err)
			}
			return conn, err
		},
		DisableCompression:    true,
		MaxIdleConnsPerHost:   1,
		ResponseHeaderTimeout: timeout,
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: timeout}
	trace := &httptrace.ClientTrace{
		GotConn:              func(i httptrace.GotConnInfo) { reused.Store(i.Reused) },
		GotFirstResponseByte: func() { firstByte.set(base) },
	}

	get := func() (int, error) {
		req, err := http.NewRequestWithContext(httptrace.WithClientTrace(ctx, trace), http.MethodGet, target, nil)
		if err != nil {
			return 0, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		return resp.StatusCode, nil
	}

	fail := func(stage string, err error) Sample {
		if de, ok := dialErr.Load().(error); ok && de != nil {
			stage, err = "dial", de
		}
		s.Stage, s.Err = stage, oneLine(err)
		s.ToErrorMs = msSince(begin)
		s.GetToErrMs = round3(float64(time.Since(base)) / 1e6)
		s.TimedOut = isTimeout(err, time.Since(base), timeout)
		return s
	}

	code, err := get()
	if err != nil {
		return fail("cold", err)
	}
	s.StatusCold = code
	s.DialMs = round3(float64(dialEnd.get()-dialStart.get()) / 1e6)
	s.ColdMs = round3(float64(firstByte.get()-dialStart.get()) / 1e6)
	s.ColdReused = reused.Load()
	if code != http.StatusNoContent {
		return fail("target", fmt.Errorf("unexpected status %d", code))
	}
	if warm {
		w0 := time.Since(base)
		code, err = get()
		if err != nil {
			return fail("warm", err)
		}
		s.StatusWarm = code
		s.WarmMs = round3(float64(firstByte.get()-int64(w0)) / 1e6)
		s.WarmReused = reused.Load()
		if code != http.StatusNoContent {
			return fail("target", fmt.Errorf("unexpected status %d", code))
		}
	}
	tr.CloseIdleConnections()
	r0 := time.Now()
	rerr := ob.Remove()
	s.RemoveMs = msSince(r0)
	ob = nil
	if rerr != nil {
		s.RemoveError = oneLine(rerr)
	}
	s.OK = true
	return s
}

// ---- process stats ----

type Snap struct {
	RSSKB       int64   `json:"rss_kb"`
	HWMKB       int64   `json:"hwm_kb"`
	Goroutines  int     `json:"goroutines"`
	HeapAllocKB uint64  `json:"heap_alloc_kb"`
	HeapInuseKB uint64  `json:"heap_inuse_kb"`
	HeapObjects uint64  `json:"heap_objects"`
	SysKB       uint64  `json:"go_sys_kb"`
	FDs         int     `json:"fds"`
	CPUms       float64 `json:"cpu_ms_total"`
	NumGC       uint32  `json:"num_gc"`
}

func procStatus(key string) int64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, key+":") {
			f := strings.Fields(line[len(key)+1:])
			if len(f) > 0 {
				v, _ := strconv.ParseInt(f[0], 10, 64)
				return v
			}
		}
	}
	return -1
}

func CPUms() float64 {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	tv := func(t syscall.Timeval) float64 { return float64(t.Sec)*1000 + float64(t.Usec)/1000 }
	return round3(tv(ru.Utime) + tv(ru.Stime))
}

func TakeSnap(gc bool, settle time.Duration) Snap {
	if gc {
		runtime.GC()
	}
	if settle > 0 {
		time.Sleep(settle)
		if gc {
			runtime.GC()
		}
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	fds := -1
	if ents, err := os.ReadDir("/proc/self/fd"); err == nil {
		fds = len(ents)
	}
	return Snap{
		RSSKB: procStatus("VmRSS"), HWMKB: procStatus("VmHWM"),
		Goroutines: runtime.NumGoroutine(), HeapAllocKB: ms.HeapAlloc / 1024,
		HeapInuseKB: ms.HeapInuse / 1024, HeapObjects: ms.HeapObjects, SysKB: ms.Sys / 1024,
		FDs: fds, CPUms: CPUms(), NumGC: ms.NumGC,
	}
}

// ---- driver ----

type runner struct {
	e       Engine
	p       *Params
	cfgs    map[Case][]byte
	timeout time.Duration
	tagSeq  atomic.Int64
}

func (r *runner) cfg(c Case) []byte {
	if b, ok := r.cfgs[c]; ok {
		return b
	}
	res, err := r.p.Resolve(c)
	if err != nil {
		panic(err)
	}
	b, err := r.e.Config(res)
	if err != nil {
		panic(err)
	}
	r.cfgs[c] = b
	return b
}

func (r *runner) tag() string { return "probe-" + strconv.FormatInt(r.tagSeq.Add(1), 10) }

func (r *runner) test(c Case, warm bool) Sample {
	return RunTest(r.e, r.p.TargetURL, c, r.tag(), r.cfg(c), r.timeout, warm)
}

func summarize(samples []Sample) map[string]any {
	var create, dial, cold, warm, remove []float64
	fails := 0
	notReused := 0
	errs := map[string]int{}
	for _, s := range samples {
		if !s.OK {
			fails++
			errs[s.Stage+": "+s.Err]++
			continue
		}
		create = append(create, s.CreateMs)
		dial = append(dial, s.DialMs)
		cold = append(cold, s.ColdMs)
		warm = append(warm, s.WarmMs)
		remove = append(remove, s.RemoveMs)
		if !s.WarmReused {
			notReused++
		}
	}
	return map[string]any{
		"n": len(samples), "ok": len(samples) - fails, "fail": fails,
		"warm_not_reused": notReused, "errors": errs,
		"create_ms": dist(create), "dial_ms": dist(dial), "cold_ms": dist(cold),
		"warm_ms": dist(warm), "remove_ms": dist(remove),
	}
}

func buildVersions(module string) map[string]string {
	out := map[string]string{"go": runtime.Version()}
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == module {
				out["engine"] = d.Version
			}
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "-tags", "-ldflags", "-trimpath", "CGO_ENABLED", "GOARCH", "GOOS":
				out["build"+s.Key] = s.Value
			}
		}
	}
	return out
}

// Main is the entry for both probes. mainEntry is the first statement of main().
func Main(mainEntry time.Time, e Engine) {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: probe <start|seq|conc|leak|errors|urltest> [flags]")
		os.Exit(2)
	}
	mode := os.Args[1]
	fs := flag.NewFlagSet(mode, flag.ExitOnError)
	paramsPath := fs.String("params", "/bench/server/params.json", "params file")
	out := fs.String("out", "", "output JSON path (default stdout)")
	n := fs.Int("n", 200, "iterations per protocol (seq)")
	workers := fs.Int("workers", 32, "workers (conc)")
	iters := fs.Int("iters", 50, "iterations per worker (conc)")
	cycles := fs.Int("cycles", 2000, "cycles (leak)")
	trials := fs.Int("trials", 3, "trials per case (errors)")
	timeout := fs.Duration("timeout", 5*time.Second, "per-test timeout")
	only := fs.String("only", "", "comma list of protocols to run (default all)")
	casesFlag := fs.String("cases", "", "errors mode: comma list of proto:variant (default the built-in set)")
	linger := fs.Duration("linger", 0, "leak mode: extra wait after the last snapshot, GC every 5 s, then snapshot again")
	_ = fs.Parse(os.Args[2:])
	if *only != "" {
		Protos = strings.Split(*only, ",")
	}

	p, err := LoadParams(*paramsPath)
	if err != nil {
		fatal(err)
	}
	startBegin := time.Now()
	if err := e.Start(); err != nil {
		fatal(fmt.Errorf("engine start: %w", err))
	}
	ready := time.Now()

	r := &runner{e: e, p: p, cfgs: map[Case][]byte{}, timeout: *timeout}
	res := map[string]any{
		"engine":     e.Name(),
		"mode":       mode,
		"versions":   buildVersions(e.Module()),
		"notes":      e.Notes(),
		"gomaxprocs": runtime.GOMAXPROCS(0),
		"numcpu":     runtime.NumCPU(),
		"goarch":     runtime.GOARCH,
		"started_at": time.Now().UTC().Format(time.RFC3339),
	}

	switch mode {
	case "start":
		if t0, err := strconv.ParseInt(os.Getenv("BENCH_T0"), 10, 64); err == nil && t0 > 0 {
			res["exec_to_main_ms"] = round3(float64(mainEntry.UnixNano()-t0) / 1e6)
			res["exec_to_ready_ms"] = round3(float64(ready.UnixNano()-t0) / 1e6)
		}
		res["main_to_ready_ms"] = round3(float64(ready.Sub(mainEntry)) / 1e6)
		res["engine_start_ms"] = round3(float64(ready.Sub(startBegin)) / 1e6)
		res["at_ready"] = TakeSnap(false, 0)
		res["idle_2s"] = TakeSnap(false, 2*time.Second)

	case "seq":
		per := map[string]any{}
		var all []Sample
		for _, proto := range Protos {
			c := Case{proto, "valid"}
			r.cfg(c)
			cpu0 := CPUms()
			t0 := time.Now()
			var ss []Sample
			for i := 0; i < *n; i++ {
				ss = append(ss, r.test(c, true))
			}
			wall := time.Since(t0)
			cpu := CPUms() - cpu0
			sum := summarize(ss)
			sum["wall_ms"] = round3(float64(wall) / 1e6)
			sum["cpu_ms_per_test"] = round3(cpu / float64(*n))
			sum["cpu_pct_of_one_core"] = round3(100 * cpu / (float64(wall) / 1e6))
			per[proto] = sum
			all = append(all, ss...)
		}
		res["n_per_proto"] = *n
		res["per_proto"] = per
		res["after"] = TakeSnap(true, time.Second)
		res["samples"] = all

	case "conc":
		for _, proto := range Protos {
			r.cfg(Case{proto, "valid"})
		}
		before := TakeSnap(true, 500*time.Millisecond)
		total := *workers * *iters
		samples := make([]Sample, total)
		cpu0 := CPUms()
		t0 := time.Now()
		var wg sync.WaitGroup
		for w := 0; w < *workers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				for j := 0; j < *iters; j++ {
					proto := Protos[(w+j)%len(Protos)]
					samples[w**iters+j] = r.test(Case{proto, "valid"}, true)
				}
			}(w)
		}
		wg.Wait()
		wall := time.Since(t0)
		cpu := CPUms() - cpu0
		immediately := TakeSnap(false, 0)
		settled := TakeSnap(true, 2*time.Second)
		per := map[string][]Sample{}
		for _, s := range samples {
			per[s.Proto] = append(per[s.Proto], s)
		}
		perSum := map[string]any{}
		for k, v := range per {
			perSum[k] = summarize(v)
		}
		res["workers"], res["iters"], res["tests"] = *workers, *iters, total
		res["wall_ms"] = round3(float64(wall) / 1e6)
		res["tests_per_sec"] = round3(float64(total) / wall.Seconds())
		res["cpu_ms"] = round3(cpu)
		res["cpu_ms_per_test"] = round3(cpu / float64(total))
		res["cpu_cores_avg"] = round3(cpu / (float64(wall) / 1e6))
		res["peak_rss_kb_vmhwm"] = immediately.HWMKB
		res["before"], res["after_immediate"], res["after_gc_settle"] = before, immediately, settled
		res["overall"] = summarize(samples)
		res["per_proto"] = perSum

	case "leak":
		mixed := func(i int) Case { return Case{Protos[i%len(Protos)], "valid"} }
		for _, proto := range Protos {
			r.cfg(Case{proto, "valid"})
		}
		s0 := TakeSnap(true, 2*time.Second)
		for i := 0; i < 60; i++ {
			r.test(mixed(i), true)
		}
		s1 := TakeSnap(true, 2*time.Second)
		bareFail := 0
		var bareErr string
		t0 := time.Now()
		for i := 0; i < *cycles; i++ {
			c := mixed(i)
			ob, err := e.Create(r.tag(), r.cfg(c))
			if err != nil {
				bareFail++
				bareErr = oneLine(err)
				continue
			}
			if err := ob.Remove(); err != nil {
				bareFail++
				bareErr = oneLine(err)
			}
		}
		bareWall := time.Since(t0)
		s2 := TakeSnap(true, 2*time.Second)
		fullFail := 0
		t1 := time.Now()
		for i := 0; i < *cycles; i++ {
			if s := r.test(mixed(i), true); !s.OK {
				fullFail++
			}
		}
		fullWall := time.Since(t1)
		s3 := TakeSnap(true, 2*time.Second)
		debug.FreeOSMemory()
		s4 := TakeSnap(false, 0)
		res["cycles"] = *cycles
		res["snap_after_start"] = s0
		res["snap_after_warmup60"] = s1
		res["snap_after_bare_create_remove"] = s2
		res["snap_after_full_tests"] = s3
		res["snap_after_free_os_memory"] = s4
		res["bare_fail"], res["bare_err"] = bareFail, bareErr
		res["bare_wall_ms"] = round3(float64(bareWall) / 1e6)
		res["full_fail"] = fullFail
		res["full_wall_ms"] = round3(float64(fullWall) / 1e6)
		res["protos"] = Protos
		if *linger > 0 {
			end := time.Now().Add(*linger)
			for time.Now().Before(end) {
				time.Sleep(5 * time.Second)
				runtime.GC()
			}
			res["linger"] = linger.String()
			res["snap_after_linger"] = TakeSnap(true, 2*time.Second)
		}

	case "errors":
		var rows []map[string]any
		cases := append([]Case{}, ErrorCases...)
		for _, proto := range Protos {
			cases = append(cases, Case{proto, "valid"})
		}
		cases = append(cases, Case{"vless_reality", "public_valid"})
		if *casesFlag != "" {
			cases = nil
			for _, c := range strings.Split(*casesFlag, ",") {
				pv := strings.SplitN(c, ":", 2)
				cases = append(cases, Case{pv[0], pv[1]})
			}
		}
		for _, c := range cases {
			var ss []Sample
			for i := 0; i < *trials; i++ {
				ss = append(ss, r.test(c, false))
			}
			var tte []float64
			ok, timeouts := 0, 0
			for _, s := range ss {
				if s.OK {
					ok++
					tte = append(tte, s.CreateMs+s.ColdMs)
				} else {
					tte = append(tte, s.ToErrorMs)
					if s.TimedOut {
						timeouts++
					}
				}
			}
			rows = append(rows, map[string]any{
				"proto": c.Proto, "variant": c.Variant, "trials": len(ss), "ok": ok,
				"timeouts": timeouts, "ms_to_result": dist(tte), "samples": ss,
			})
		}
		res["cases"] = rows

	case "urltest":
		var rows []map[string]any
		for _, proto := range Protos {
			c := Case{proto, "valid"}
			for i := 0; i < 5; i++ {
				ob, err := e.Create(r.tag(), r.cfg(c))
				if err != nil {
					rows = append(rows, map[string]any{"proto": proto, "err": oneLine(err)})
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), *timeout)
				t0 := time.Now()
				delay, err := e.URLTest(ctx, ob, p.TargetURL)
				wall := msSince(t0)
				cancel()
				_ = ob.Remove()
				rows = append(rows, map[string]any{"proto": proto, "run": i, "reported_ms": delay, "wall_ms": wall, "err": oneLine(err)})
			}
		}
		res["runs"] = rows

	default:
		fatal(fmt.Errorf("unknown mode %q", mode))
	}

	res["final"] = TakeSnap(false, 0)
	b, _ := json.MarshalIndent(res, "", "  ")
	if *out == "" {
		os.Stdout.Write(append(b, '\n'))
		return
	}
	if err := os.WriteFile(*out, append(b, '\n'), 0o644); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "fatal:", err)
	os.Exit(1)
}
