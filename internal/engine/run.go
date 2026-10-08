package engine

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/measure"
	"github.com/LatticeNet/lattice-probe/internal/policy"
	"github.com/LatticeNet/lattice-probe/internal/spec"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-quic/hysteria"
	"github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// run is the measurement half of one probe.
type run struct {
	e    *Engine
	plan *policy.Plan
	st   *guardState
	test adapter.Outbound
	opts []option.Outbound
	res  *spec.Result
}

// sampleCtx bounds one network step by the per-sample deadline and by
// whatever is left of the request.
func (r *run) sampleCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, r.e.cfg.SampleTimeout)
}

func (r *run) httpOptions() measure.Options {
	return measure.Options{RootCAs: r.e.cfg.RootCAs, UserAgent: "lattice-probe/" + spec.Version}
}

// measure runs the checks in order and returns the stage the probe ended
// in, with the message that explains it.
func (r *run) measure(ctx context.Context) (spec.Stage, string) {
	serverErr := r.checkServer(ctx)
	if r.st.Refused() != nil {
		return spec.StagePolicy, ""
	}
	// A refused or silent TCP connect is conclusive. A QUIC check is not
	// (an obfuscation the probe cannot speak drops it), so the targets
	// still run and decide.
	if serverErr != nil && r.res.Server.Network == "tcp" {
		return spec.StageServer, "server unreachable: " + measure.OneLine(serverErr)
	}

	out := r.sampleTargets(ctx)
	if r.st.Refused() != nil {
		return spec.StagePolicy, ""
	}
	if !out.anyOK && !out.gotResponse {
		switch {
		case serverErr != nil:
			// Nothing worked and the QUIC check heard nothing either: the
			// server is the most specific explanation there is.
			return spec.StageServer, "server unreachable: " + measure.OneLine(serverErr)
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			return spec.StageTimeout, fmt.Sprintf("probe ran out of time after %d ms: %s", r.plan.Timeout.Milliseconds(), out.firstErr)
		case out.timeouts > 0 && out.otherFails == 0:
			return spec.StageTimeout, out.firstErr
		default:
			return spec.StageHandshake, out.firstErr
		}
	}

	if out.anyOK {
		r.afterTargets(ctx)
	}
	for _, t := range r.res.Targets {
		if t.OK == 0 {
			return spec.StageTarget, t.ID + ": " + t.Error
		}
	}
	return spec.StageOK, ""
}

// checkServer connects to the first hop of the tested chain directly, the
// only server the probe itself reaches: TCP connect for TCP protocols, a
// QUIC handshake attempt for QUIC ones.
func (r *run) checkServer(ctx context.Context) error {
	root := r.plan.Outbounds[r.plan.Root]
	dest := M.ParseSocksaddrHostPort(root.Host, root.Port)
	sctx, cancel := r.sampleCtx(ctx)
	defer cancel()
	var rtt time.Duration
	var err error
	if r.res.Server.Network == "tcp" {
		// Resolve before the clock starts so the RTT times the connect
		// alone; the dial below then reads the guard's checked cache.
		if _, err := r.st.resolve(sctx, dest); err != nil {
			return err
		}
		rtt, err = measure.TCPConnect(sctx, func(ctx context.Context) (net.Conn, error) {
			return r.st.dial(ctx, N.NetworkTCP, dest)
		})
	} else {
		rtt, err = r.quicReach(sctx, root.Type, r.opts[r.plan.Root], dest)
	}
	if err != nil {
		return err
	}
	r.res.Server.Reachable = true
	r.res.Server.RTTMS = measure.MS(rtt)
	return nil
}

func (r *run) quicReach(ctx context.Context, outboundType string, opt option.Outbound, dest M.Socksaddr) (time.Duration, error) {
	conn, err := r.st.dial(ctx, N.NetworkUDP, dest)
	if err != nil {
		return 0, err
	}
	var pc net.PacketConn = bufio.NewUnbindPacketConn(conn)
	var tlsOpt *option.OutboundTLSOptions
	alpn := []string{"h3"}
	switch o := opt.Options.(type) {
	case *option.Hysteria2OutboundOptions:
		tlsOpt = o.TLS
		if o.Obfs != nil && o.Obfs.Type == hysteria2.ObfsTypeSalamander && o.Obfs.Password != "" {
			pc = hysteria2.NewSalamanderConn(pc, []byte(o.Obfs.Password))
		}
	case *option.HysteriaOutboundOptions:
		tlsOpt = o.TLS
		alpn = []string{"hysteria"}
		if o.Obfs != "" {
			pc = hysteria.NewXPlusPacketConn(pc, []byte(o.Obfs))
		}
	case *option.TUICOutboundOptions:
		tlsOpt = o.TLS
	}
	serverName := dest.AddrString()
	if dest.IsIP() {
		serverName = ""
	}
	if tlsOpt != nil {
		if tlsOpt.ServerName != "" {
			serverName = tlsOpt.ServerName
		}
		if len(tlsOpt.ALPN) > 0 {
			alpn = tlsOpt.ALPN
		}
	}
	return measure.QUICReach(ctx, pc, conn.RemoteAddr(), serverName, alpn)
}

type targetOutcome struct {
	anyOK       bool
	gotResponse bool
	timeouts    int
	otherFails  int
	firstErr    string
}

// sampleTargets measures each target in turn. It stops early when the
// proxy itself is clearly broken: a target stops after its first timeout or
// its second failure in a row while nothing has passed, and the remaining
// targets are skipped when the first one got no answer at all.
func (r *run) sampleTargets(ctx context.Context) targetOutcome {
	var out targetOutcome
	opt := r.httpOptions()
	for ti, target := range r.plan.Targets {
		tr := spec.TargetResult{ID: target.ID}
		var colds, warms []float64
		failsInRow := 0
		for range r.plan.Samples {
			if ctx.Err() != nil {
				break
			}
			sctx, cancel := r.sampleCtx(ctx)
			s := measure.HTTPSample(sctx, r.test, target.URL, target.Expect, opt)
			cancel()
			tr.Of++
			if s.Status != 0 {
				tr.Status = s.Status
				out.gotResponse = true
			}
			if s.OK(target.Expect) {
				tr.OK++
				out.anyOK = true
				failsInRow = 0
				colds = append(colds, measure.MS(s.Cold))
				if s.WarmOK {
					warms = append(warms, measure.MS(s.Warm))
				}
				continue
			}
			msg := measure.OneLine(s.Err)
			if tr.Error == "" {
				tr.Error = msg
			}
			if out.firstErr == "" {
				out.firstErr = msg
			}
			if s.TimedOut {
				out.timeouts++
			} else {
				out.otherFails++
			}
			failsInRow++
			if tr.OK == 0 && (s.TimedOut || failsInRow >= 2) {
				break
			}
		}
		tr.ColdMS = measure.Summarize(colds)
		tr.WarmMS = measure.Summarize(warms)
		if tr.OK == tr.Of && tr.Of > 0 {
			tr.Error = ""
		}
		r.res.Targets = append(r.res.Targets, tr)
		if ti == 0 && !out.anyOK && !out.gotResponse {
			for _, rest := range r.plan.Targets[1:] {
				r.res.Targets = append(r.res.Targets, spec.TargetResult{ID: rest.ID, Error: "not run: no sample reached " + target.ID})
			}
			break
		}
	}
	return out
}

// afterTargets runs the exit and UDP checks side by side, then the
// throughput download, which would distort the other two.
func (r *run) afterTargets(ctx context.Context) {
	opt := r.httpOptions()
	var wg sync.WaitGroup
	wg.Go(func() {
		sctx, cancel := r.sampleCtx(ctx)
		defer cancel()
		if exit, err := measure.Exit(sctx, r.test, r.e.cfg.TraceURL, opt); err == nil {
			r.res.Exit = exit
		}
	})
	if r.plan.UDP && slices.Contains(r.test.Network(), N.NetworkUDP) {
		wg.Go(func() {
			sctx, cancel := r.sampleCtx(ctx)
			defer cancel()
			rtt, err := measure.UDPDNS(sctx, r.test, r.e.cfg.DNSServer, r.e.cfg.DNSName)
			u := &spec.UDP{OK: err == nil, RTTMS: measure.MS(rtt)}
			if err != nil {
				u.Error = measure.OneLine(err)
			}
			r.res.UDP = u
		})
	}
	wg.Wait()
	if r.plan.Throughput && ctx.Err() == nil {
		url := fmt.Sprintf(r.e.cfg.ThroughputURL, r.plan.ThroughputBytes)
		if tp, err := measure.Download(ctx, r.test, url, opt); err == nil {
			r.res.Throughput = tp
		}
	}
}
