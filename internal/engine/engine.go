// Package engine runs probes inside one long-lived sing-box instance. Each
// request's outbounds are decoded with the sing-box option registry,
// created at runtime under fresh tags, measured, and removed on every exit
// path; nothing is written to disk and nothing reloads.
package engine

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"strings"
	"sync/atomic"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/measure"
	"github.com/LatticeNet/lattice-probe/internal/policy"
	"github.com/LatticeNet/lattice-probe/internal/spec"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
)

const singBoxModule = "github.com/sagernet/sing-box"

// pinnedCoreVersion is the sing-box version go.mod requires. Release
// binaries read the real version from their build info; test binaries carry
// none, so they fall back to this. A test keeps it equal to go.mod.
const pinnedCoreVersion = "1.13.19"

// Config describes where an engine reaches and what it trusts. The zero
// value of every field selects the production default.
type Config struct {
	Targets  []spec.Target
	Policy   *policy.Policy
	Resolver policy.Resolver

	TraceURL      string // exit check, default https://www.cloudflare.com/cdn-cgi/trace
	DNSServer     string // UDP check, default 1.1.1.1:53
	DNSName       string // name queried by the UDP check, default cloudflare.com
	ThroughputURL string // fmt pattern taking the byte count, default speed.cloudflare.com
	RootCAs       *x509.CertPool
	SampleTimeout time.Duration // default 5 s
}

// Engine owns the sing-box instance. It is safe for concurrent use.
type Engine struct {
	cfg         Config
	ctx         context.Context
	cancel      context.CancelFunc
	box         *box.Box
	seq         atomic.Uint64
	coreVersion string
}

// New starts the sing-box instance: no inbounds, one direct outbound as the
// default, and the guard type registered beside the standard protocols.
func New(cfg Config) (*Engine, error) {
	if len(cfg.Targets) == 0 {
		cfg.Targets = spec.DefaultTargets()
	}
	if cfg.Policy == nil {
		cfg.Policy = &policy.Policy{}
	}
	if cfg.Resolver == nil {
		cfg.Resolver = &net.Resolver{PreferGo: true}
	}
	if cfg.TraceURL == "" {
		cfg.TraceURL = "https://www.cloudflare.com/cdn-cgi/trace"
	}
	if cfg.DNSServer == "" {
		cfg.DNSServer = "1.1.1.1:53"
	}
	if cfg.DNSName == "" {
		cfg.DNSName = "cloudflare.com"
	}
	if cfg.ThroughputURL == "" {
		cfg.ThroughputURL = "https://speed.cloudflare.com/__down?bytes=%d"
	}
	if cfg.SampleTimeout <= 0 {
		cfg.SampleTimeout = spec.SampleTimeout
	}

	registry := include.OutboundRegistry()
	outbound.Register[guardOptions](registry, guardType, newGuard)
	ctx, cancel := context.WithCancel(context.Background())
	ctx = box.Context(ctx, include.InboundRegistry(), registry, include.EndpointRegistry(), include.DNSTransportRegistry(), include.ServiceRegistry())
	inst, err := box.New(box.Options{
		Context: ctx,
		Options: option.Options{
			Log:       &option.LogOptions{Disabled: true},
			Outbounds: []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}},
		},
	})
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create sing-box instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		cancel()
		return nil, fmt.Errorf("start sing-box instance: %w", err)
	}
	return &Engine{cfg: cfg, ctx: ctx, cancel: cancel, box: inst, coreVersion: coreVersion()}, nil
}

// Close stops the sing-box instance.
func (e *Engine) Close() error {
	err := e.box.Close()
	e.cancel()
	return err
}

// Targets returns the configured target list.
func (e *Engine) Targets() []spec.Target { return e.cfg.Targets }

// CoreVersion is the sing-box version compiled in, without the leading v.
func (e *Engine) CoreVersion() string { return e.coreVersion }

func (e *Engine) info() spec.EngineInfo {
	return spec.EngineInfo{Name: spec.EngineName, Version: e.coreVersion}
}

// outboundCount reports how many outbounds the instance holds, for tests
// that prove nothing is left behind.
func (e *Engine) outboundCount() int { return len(e.box.Outbound().Outbounds()) }

func coreVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, dep := range bi.Deps {
			if dep.Path == singBoxModule {
				if dep.Replace != nil {
					dep = dep.Replace
				}
				return strings.TrimPrefix(dep.Version, "v")
			}
		}
	}
	return pinnedCoreVersion
}

// Run probes one request. A *spec.RequestError means the request was
// refused (400); any other error is an internal failure. Everything an
// outbound did wrong is reported inside the Result.
func (e *Engine) Run(ctx context.Context, req *spec.Request) (*spec.Result, error) {
	began := time.Now()
	plan, err := policy.Parse(req, e.cfg.Targets)
	if err != nil {
		return nil, err
	}
	res := &spec.Result{Targets: []spec.TargetResult{}, Engine: e.info(), Types: plan.Types()}
	res.Server = spec.Server{Address: plan.Outbounds[plan.Root].Server(), Network: networkOf(plan.Outbounds[plan.Root].Type)}

	ctx, cancel := context.WithTimeout(ctx, plan.Timeout)
	defer cancel()

	n := e.seq.Add(1)
	tags := make([]string, len(plan.Outbounds))
	for i := range tags {
		tags[i] = fmt.Sprintf("probe-%d-%d", n, i)
	}
	guardTag := fmt.Sprintf("probe-%d-guard", n)

	opts := make([]option.Outbound, len(plan.Outbounds))
	for i, ob := range plan.Outbounds {
		raw, err := rewrite(ob, plan, tags, guardTag)
		if err != nil {
			return nil, err
		}
		opts[i], err = sjson.UnmarshalExtendedContext[option.Outbound](e.ctx, raw)
		if err != nil {
			return e.finish(res, plan, began, spec.StageDecode, fmt.Sprintf("outbounds[%d] (%s): %s", i, ob.Type, measure.OneLine(err))), nil
		}
	}

	// Outbounds live in a context of their own, cancelled after they are
	// removed, so nothing they started can outlive the request.
	octx, ocancel := context.WithCancel(e.ctx)
	st := newGuardState(e.cfg.Policy, e.cfg.Resolver)
	manager := e.box.Outbound()
	var created []string
	defer func() {
		cancel()
		// Dependents first: sing-box's Remove refuses, without closing it,
		// an outbound another one still depends on.
		for i := len(created) - 1; i >= 0; i-- {
			_ = manager.Remove(created[i])
		}
		ocancel()
	}()
	logger := e.box.LogFactory().NewLogger("probe")
	if err := manager.Create(octx, e.box.Router(), logger, guardTag, guardType, &guardOptions{state: st}); err != nil {
		return nil, fmt.Errorf("create guard outbound: %w", err)
	}
	created = append(created, guardTag)
	for _, i := range plan.Order {
		if err := manager.Create(octx, e.box.Router(), logger, tags[i], opts[i].Type, opts[i].Options); err != nil {
			return e.finish(res, plan, began, spec.StageCreate, fmt.Sprintf("outbounds[%d] (%s): %s", i, plan.Outbounds[i].Type, measure.OneLine(err))), nil
		}
		created = append(created, tags[i])
	}
	res.Valid = true

	if err := e.checkServers(ctx, plan); err != nil {
		var refusal *policy.Refusal
		if errors.As(err, &refusal) {
			return nil, spec.Refuse(refusal.Error())
		}
		return e.finish(res, plan, began, spec.StageServer, measure.OneLine(err)), nil
	}

	test, ok := manager.Outbound(tags[plan.Test])
	if !ok {
		return nil, errors.New("tested outbound vanished after create")
	}
	r := &run{e: e, plan: plan, st: st, test: test, opts: opts, res: res}
	stage, msg := r.measure(ctx)
	if refusal := st.Refused(); refusal != nil {
		return nil, spec.Refuse(refusal.Error())
	}
	return e.finish(res, plan, began, stage, msg), nil
}

func (e *Engine) finish(res *spec.Result, plan *policy.Plan, began time.Time, stage spec.Stage, msg string) *spec.Result {
	res.Stage = stage
	res.Error = policy.Redact(msg, plan.Secrets)
	for i := range res.Targets {
		res.Targets[i].Error = policy.Redact(res.Targets[i].Error, plan.Secrets)
	}
	if res.UDP != nil {
		res.UDP.Error = policy.Redact(res.UDP.Error, plan.Secrets)
	}
	res.TookMS = measure.MS(time.Since(began))
	return res
}

// checkServers applies the address policy to every server of the request
// before anything connects to one. Names are resolved and every address
// they resolve to must pass. This is the early, readable refusal; the
// guard repeats the check on whatever it actually dials.
func (e *Engine) checkServers(ctx context.Context, plan *policy.Plan) error {
	for _, ob := range plan.Outbounds {
		if a, ok := ob.Literal(); ok {
			if r := e.cfg.Policy.Check(a); r != nil {
				return r
			}
			continue
		}
		rctx, cancel := context.WithTimeout(ctx, guardResolveTimeout)
		addrs, err := e.cfg.Resolver.LookupNetIP(rctx, "ip", ob.Host)
		cancel()
		if err != nil {
			return fmt.Errorf("resolve %s: %w", ob.Host, err)
		}
		if len(addrs) == 0 {
			return fmt.Errorf("resolve %s: no addresses", ob.Host)
		}
		for _, a := range addrs {
			if r := e.cfg.Policy.Check(a); r != nil {
				r.Host = ob.Host
				return r
			}
		}
	}
	return nil
}

// rewrite gives an outbound its fresh tag and points its detour at the
// fresh tag of its request-local detour, or at the guard. domain_resolver
// is dropped: it names a DNS server of a config the probe does not have,
// and the guard resolves server names itself.
func rewrite(ob policy.Outbound, plan *policy.Plan, tags []string, guardTag string) ([]byte, error) {
	out := make(map[string]json.RawMessage, len(ob.Raw)+1)
	for k, v := range ob.Raw {
		out[k] = v
	}
	delete(out, "domain_resolver")
	detour := guardTag
	if ob.Detour != "" {
		for j, other := range plan.Outbounds {
			if other.Tag == ob.Detour {
				detour = tags[j]
			}
		}
	}
	var err error
	if out["tag"], err = json.Marshal(tags[ob.Index]); err != nil {
		return nil, err
	}
	if out["detour"], err = json.Marshal(detour); err != nil {
		return nil, err
	}
	return json.Marshal(out)
}

func networkOf(outboundType string) string {
	if policy.QUICTypes[outboundType] {
		return "udp"
	}
	return "tcp"
}
