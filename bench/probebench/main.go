// Command probebench measures the engine against a local lab, with the lab
// and the engine in separate processes so the engine's memory is measured
// alone:
//
//	probebench lab -out lab.json &        # start the lab, write its parameters
//	probebench run -lab lab.json          # measure the engine in this process
//
// Memory figures come from /proc/self/status and are only reported on Linux.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/engine"
	"github.com/LatticeNet/lattice-probe/internal/measure"
	"github.com/LatticeNet/lattice-probe/internal/policy"
	"github.com/LatticeNet/lattice-probe/internal/spec"
	"github.com/LatticeNet/lattice-probe/internal/testkit"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: probebench lab -out FILE | run -lab FILE [-n N]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "lab":
		err = lab(os.Args[2:])
	case "run":
		err = run(os.Args[2:])
	default:
		err = fmt.Errorf("unknown mode %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "probebench:", err)
		os.Exit(1)
	}
}

func lab(args []string) error {
	fs := flag.NewFlagSet("lab", flag.ExitOnError)
	out := fs.String("out", "lab.json", "where to write the lab parameters")
	_ = fs.Parse(args)
	l, err := testkit.Start()
	if err != nil {
		return err
	}
	defer l.Close()
	data, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*out, data, 0o600); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "lab ready:", *out)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	return nil
}

type protoReport struct {
	Proto          string    `json:"proto"`
	Runs           int       `json:"runs"`
	OK             int       `json:"ok"`
	ServerNetwork  string    `json:"server_network"`
	ServerRTT      spec.Dist `json:"server_rtt_ms"`
	ColdP50        spec.Dist `json:"cold_p50_ms"`
	WarmP50        spec.Dist `json:"warm_p50_ms"`
	UDPOK          int       `json:"udp_ok"`
	UDPRTT         spec.Dist `json:"udp_rtt_ms"`
	UDPError       string    `json:"udp_error,omitempty"`
	Took           spec.Dist `json:"took_ms"`
	ThroughputMbps []float64 `json:"throughput_mbps"`
	ThroughputSec  []float64 `json:"throughput_s"`
}

type report struct {
	Arch        string        `json:"arch"`
	GOMAXPROCS  int           `json:"gomaxprocs"`
	CPUMax      string        `json:"cgroup_cpu_max,omitempty"`
	IdleRSSKiB  int64         `json:"idle_rss_kib"`
	IdleHeapKiB uint64        `json:"idle_heap_kib"`
	Protocols   []protoReport `json:"protocols"`
	Concurrent  struct {
		Workers      int     `json:"workers"`
		Probes       int     `json:"probes"`
		OK           int     `json:"ok"`
		WallS        float64 `json:"wall_s"`
		PerSecond    float64 `json:"probes_per_s"`
		PeakRSSKiB   int64   `json:"peak_rss_kib"`
		AfterRSSKiB  int64   `json:"rss_after_kib"`
		GoroutinesIn int     `json:"goroutines_before"`
		GoroutinesAt int     `json:"goroutines_after_gc"`
	} `json:"concurrent"`
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	labPath := fs.String("lab", "lab.json", "lab parameters written by probebench lab")
	n := fs.Int("n", 20, "probes per protocol")
	tpBytes := fs.Int64("throughput-bytes", 10_000_000, "bytes per throughput download")
	tpRuns := fs.Int("throughput-runs", 3, "throughput downloads per protocol")
	workers := fs.Int("workers", spec.MaxInflight, "concurrent probes in the load phase")
	perWorker := fs.Int("per-worker", 10, "probes per worker in the load phase")
	_ = fs.Parse(args)

	data, err := os.ReadFile(*labPath)
	if err != nil {
		return err
	}
	var l testkit.Lab
	if err := json.Unmarshal(data, &l); err != nil {
		return err
	}
	eng, err := engine.New(engine.Config{
		Targets:       l.Targets(),
		Policy:        &policy.Policy{Allow: testkit.LoopbackOnly},
		TraceURL:      l.TraceURL(),
		DNSServer:     l.DNSAddr,
		DNSName:       "lab.test",
		ThroughputURL: l.DownloadURL(),
	})
	if err != nil {
		return err
	}
	defer eng.Close()

	var rep report
	rep.Arch = runtime.GOARCH
	rep.GOMAXPROCS = runtime.GOMAXPROCS(0)
	if b, err := os.ReadFile("/sys/fs/cgroup/cpu.max"); err == nil {
		rep.CPUMax = strings.TrimSpace(string(b))
	}
	time.Sleep(2 * time.Second)
	runtime.GC()
	rep.IdleRSSKiB = procStatus("VmRSS")
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	rep.IdleHeapKiB = ms.HeapAlloc >> 10

	probe := func(proto string, mutate func(*spec.Request)) (*spec.Result, error) {
		req := &spec.Request{
			Outbounds: []json.RawMessage{l.OutboundJSON(proto, "", "line")},
			Targets:   []string{"lab-204"},
			Samples:   5,
			UDP:       true,
			TimeoutMS: 30000,
		}
		if mutate != nil {
			mutate(req)
		}
		return eng.Run(context.Background(), req)
	}

	for _, proto := range testkit.Protocols {
		pr := protoReport{Proto: proto, Runs: *n}
		var server, cold, warm, udp, took []float64
		for range *n {
			res, err := probe(proto, nil)
			if err != nil {
				return err
			}
			pr.ServerNetwork = res.Server.Network
			if res.Stage == spec.StageOK {
				pr.OK++
			}
			if res.Server.Reachable {
				server = append(server, res.Server.RTTMS)
			}
			if len(res.Targets) > 0 && res.Targets[0].OK > 0 {
				cold = append(cold, res.Targets[0].ColdMS.P50)
				warm = append(warm, res.Targets[0].WarmMS.P50)
			}
			if res.UDP != nil {
				if res.UDP.OK {
					pr.UDPOK++
					udp = append(udp, res.UDP.RTTMS)
				} else if pr.UDPError == "" {
					pr.UDPError = res.UDP.Error
				}
			}
			took = append(took, res.TookMS)
		}
		pr.ServerRTT, pr.ColdP50, pr.WarmP50 = measure.Summarize(server), measure.Summarize(cold), measure.Summarize(warm)
		pr.UDPRTT, pr.Took = measure.Summarize(udp), measure.Summarize(took)
		for range *tpRuns {
			res, err := probe(proto, func(r *spec.Request) {
				r.Samples, r.UDP, r.Throughput, r.ThroughputBytes = 1, false, true, *tpBytes
			})
			if err != nil {
				return err
			}
			if res.Throughput != nil {
				pr.ThroughputMbps = append(pr.ThroughputMbps, res.Throughput.Mbps)
				pr.ThroughputSec = append(pr.ThroughputSec, res.Throughput.Seconds)
			}
		}
		rep.Protocols = append(rep.Protocols, pr)
	}

	runtime.GC()
	time.Sleep(time.Second)
	c := &rep.Concurrent
	c.Workers, c.Probes = *workers, *workers**perWorker
	c.GoroutinesIn = runtime.NumGoroutine()
	resetPeak()
	var mu sync.Mutex
	var wg sync.WaitGroup
	start := time.Now()
	for w := range *workers {
		wg.Go(func() {
			for i := range *perWorker {
				proto := testkit.Protocols[(w+i)%len(testkit.Protocols)]
				res, err := probe(proto, func(r *spec.Request) { r.Samples = 1 })
				if err == nil && res.Stage == spec.StageOK {
					mu.Lock()
					c.OK++
					mu.Unlock()
				}
			}
		})
	}
	wg.Wait()
	c.WallS = time.Since(start).Seconds()
	c.PerSecond = float64(c.Probes) / c.WallS
	c.PeakRSSKiB = procStatus("VmHWM")
	time.Sleep(2 * time.Second)
	runtime.GC()
	c.AfterRSSKiB = procStatus("VmRSS")
	c.GoroutinesAt = runtime.NumGoroutine()

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

// procStatus reads a kB field of /proc/self/status, or -1 off Linux.
func procStatus(key string) int64 {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return -1
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, key+":"); ok {
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				v, _ := strconv.ParseInt(fields[0], 10, 64)
				return v
			}
		}
	}
	return -1
}

// resetPeak clears VmHWM so the load phase's peak is its own (Linux 4.0+).
func resetPeak() {
	_ = os.WriteFile("/proc/self/clear_refs", []byte("5"), 0)
}
