// Command probectl tests one outbound file and prints the result. It runs
// the engine in-process by default, or talks to a running lattice-probe
// with -socket. -health checks a running daemon and is what the container
// health check calls.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/engine"
	"github.com/LatticeNet/lattice-probe/internal/policy"
	"github.com/LatticeNet/lattice-probe/internal/spec"
)

const usage = `usage: probectl [flags] OUTBOUND.json
       probectl -health [-socket PATH]

OUTBOUND.json holds one sing-box outbound object, or an array of them for a
chain ("-" reads standard input). Without -socket the engine runs in this
process; with it, the request goes to a running lattice-probe.

`

func main() {
	os.Exit(run())
}

func run() int {
	fs := flag.NewFlagSet("probectl", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), usage)
		fs.PrintDefaults()
	}
	var (
		socket      = fs.String("socket", "", "talk to the lattice-probe serving this socket instead of running in-process")
		health      = fs.Bool("health", false, "check a running daemon's /v1/health and exit (uses -socket or LATTICE_PROBE_SOCKET)")
		test        = fs.String("test", "", "tag of the outbound to measure when the file holds several")
		targets     = fs.String("targets", "", "comma-separated target ids (default: the first configured target)")
		samples     = fs.Int("samples", 0, "samples per target, 1 to 10 (default 5)")
		udp         = fs.Bool("udp", false, "also test UDP with a DNS query through the outbound")
		throughput  = fs.Bool("throughput", false, "also download a fixed size through the outbound (costs real traffic)")
		tpBytes     = fs.Int64("throughput-bytes", 0, "bytes to download, at most 25000000 (default 10000000)")
		timeout     = fs.Int("timeout", 0, "overall deadline in milliseconds, 1000 to 30000 (default 15000)")
		allow       = fs.String("allow", "", "in-process only: comma-separated CIDRs exempt from the address policy, for lab servers")
		targetsFile = fs.String("targets-file", "", "in-process only: targets file replacing the built-in list")
		asJSON      = fs.Bool("json", false, "print the raw JSON answer")
	)
	if err := fs.Parse(os.Args[1:]); err != nil {
		return 2
	}
	if *health {
		return checkHealth(socketPath(*socket))
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	outbounds, err := readOutbounds(fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "probectl:", err)
		return 2
	}
	req := &spec.Request{
		Outbounds:       outbounds,
		Test:            *test,
		Samples:         *samples,
		UDP:             *udp,
		Throughput:      *throughput,
		ThroughputBytes: *tpBytes,
		TimeoutMS:       *timeout,
	}
	if *targets != "" {
		req.Targets = strings.Split(*targets, ",")
	}

	var res *spec.Result
	if *socket != "" {
		res, err = remote(*socket, req)
	} else {
		res, err = local(req, *allow, *targetsFile)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "probectl:", err)
		return 2
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	} else {
		printResult(os.Stdout, res)
	}
	if res.Stage != spec.StageOK {
		return 1
	}
	return 0
}

func socketPath(flagValue string) string {
	if flagValue != "" {
		return flagValue
	}
	if env := os.Getenv("LATTICE_PROBE_SOCKET"); env != "" {
		return env
	}
	return spec.DefaultSocket
}

// readOutbounds accepts one outbound object or an array of them.
func readOutbounds(path string) ([]json.RawMessage, error) {
	var data []byte
	var err error
	if path == "-" {
		data, err = io.ReadAll(io.LimitReader(os.Stdin, spec.MaxBodyBytes+1))
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, err
	}
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '[' {
		var list []json.RawMessage
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return list, nil
	}
	if !json.Valid(data) {
		return nil, fmt.Errorf("%s is not valid JSON", path)
	}
	return []json.RawMessage{data}, nil
}

func local(req *spec.Request, allowList, targetsFile string) (*spec.Result, error) {
	allow, err := policy.ParsePrefixes(allowList)
	if err != nil {
		return nil, err
	}
	targets, err := spec.LoadTargets(targetsFile)
	if err != nil {
		return nil, err
	}
	eng, err := engine.New(engine.Config{Targets: targets, Policy: &policy.Policy{Allow: allow}})
	if err != nil {
		return nil, err
	}
	defer eng.Close()
	res, err := eng.Run(context.Background(), req)
	var refusal *spec.RequestError
	if errors.As(err, &refusal) {
		return nil, fmt.Errorf("refused (%s): %s", refusal.Stage, refusal.Message)
	}
	return res, err
}

func unixClient(path string, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		},
	}
}

func remote(path string, req *spec.Request) (*spec.Result, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	resp, err := unixClient(path, 40*time.Second).Post("http://probe/v1/probe", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var e spec.ErrorBody
		if json.Unmarshal(data, &e) == nil && e.Error.Message != "" {
			return nil, fmt.Errorf("refused with %d (%s): %s", resp.StatusCode, e.Error.Stage, e.Error.Message)
		}
		return nil, fmt.Errorf("probe answered %d", resp.StatusCode)
	}
	var res spec.Result
	if err := json.Unmarshal(data, &res); err != nil {
		return nil, err
	}
	return &res, nil
}

func checkHealth(path string) int {
	resp, err := unixClient(path, 3*time.Second).Get("http://probe/v1/health")
	if err != nil {
		fmt.Fprintln(os.Stderr, "probectl: health:", err)
		return 1
	}
	defer resp.Body.Close()
	var h spec.Health
	if resp.StatusCode != http.StatusOK || json.NewDecoder(resp.Body).Decode(&h) != nil {
		fmt.Fprintln(os.Stderr, "probectl: health answered", resp.StatusCode)
		return 1
	}
	fmt.Printf("ok: probe %s, %s %s, up %d s, %d/%d in flight\n", h.ProbeVersion, h.Engine, h.CoreVersion, h.UptimeS, h.Inflight, h.MaxInflight)
	return 0
}

var stageWords = map[spec.Stage]string{
	spec.StageOK:        "works",
	spec.StageDecode:    "invalid: sing-box could not decode the outbound",
	spec.StageCreate:    "invalid: sing-box refused to create the outbound",
	spec.StageServer:    "failed: the server did not answer",
	spec.StageHandshake: "failed: the proxy handshake failed, or the server reached no target",
	spec.StageTarget:    "partly failed: a target did not answer as expected",
	spec.StageTimeout:   "failed: timed out",
}

func printResult(w io.Writer, r *spec.Result) {
	fmt.Fprintf(w, "verdict     %s\n", stageWords[r.Stage])
	if r.Error != "" {
		fmt.Fprintf(w, "error       %s\n", r.Error)
	}
	reach := "unreachable"
	if r.Server.Reachable {
		reach = fmt.Sprintf("reachable, %.1f ms", r.Server.RTTMS)
	}
	fmt.Fprintf(w, "server      %s over %s, %s\n", r.Server.Address, r.Server.Network, reach)
	if len(r.Targets) > 0 {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "target\tok/of\tcold min/p50/p90 ms\twarm min/p50/p90 ms\tstatus\terror")
		for _, t := range r.Targets {
			fmt.Fprintf(tw, "%s\t%d/%d\t%.1f / %.1f / %.1f\t%.1f / %.1f / %.1f\t%d\t%s\n",
				t.ID, t.OK, t.Of, t.ColdMS.Min, t.ColdMS.P50, t.ColdMS.P90, t.WarmMS.Min, t.WarmMS.P50, t.WarmMS.P90, t.Status, t.Error)
		}
		tw.Flush()
	}
	if r.Exit != nil {
		fmt.Fprintf(w, "exit        %s %s %s\n", r.Exit.IP, r.Exit.Loc, r.Exit.Colo)
	}
	if r.UDP != nil {
		if r.UDP.OK {
			fmt.Fprintf(w, "udp         ok, %.1f ms\n", r.UDP.RTTMS)
		} else {
			fmt.Fprintf(w, "udp         failed: %s\n", r.UDP.Error)
		}
	}
	if r.Throughput != nil {
		fmt.Fprintf(w, "throughput  %d bytes in %.3f s, %.1f Mbps\n", r.Throughput.Bytes, r.Throughput.Seconds, r.Throughput.Mbps)
	}
	fmt.Fprintf(w, "engine      %s %s, took %.1f ms\n", r.Engine.Name, r.Engine.Version, r.TookMS)
}
