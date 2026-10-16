// Package spec holds the wire types and limits of the probe's socket API.
// Every other package builds against these, so the JSON tags here are the
// contract with lattice-server.
package spec

import (
	"encoding/json"
	"time"
)

// Version is the probe's own version. Release builds set it with
// -ldflags "-X github.com/LatticeNet/lattice-probe/internal/spec.Version=...".
var Version = "0.1.0-alpha.2"

const (
	EngineName = "sing-box"

	DefaultSocket = "/run/lattice-probe/probe.sock"

	MaxBodyBytes = 64 << 10
	MaxOutbounds = 8
	MaxInflight  = 32

	DefaultSamples = 5
	MinSamples     = 1
	MaxSamples     = 10

	DefaultTimeoutMS = 15000
	MinTimeoutMS     = 1000
	MaxTimeoutMS     = 30000

	DefaultThroughputBytes = 10_000_000
	MaxThroughputBytes     = 25_000_000

	SampleTimeout = 5 * time.Second

	// MaxTargetsPerRun bounds the targets one request measures, built-in
	// and custom together.
	MaxTargetsPerRun = 16
	// MaxCustomURLBytes bounds a custom target's URL.
	MaxCustomURLBytes = 2048
	// MaxBodyContainsBytes bounds a custom target's body needle.
	MaxBodyContainsBytes = 256
	// BodyMatchWindow is how much of a response body is searched for a
	// custom target's needle. The body itself is never returned.
	BodyMatchWindow = 64 << 10
	// CustomTargetPrefix starts every custom target id. A targets file may
	// not use it, so a custom id can never name a configured target.
	CustomTargetPrefix = "custom-"

	// CapabilityCustomTargets in Health.Capabilities says this probe
	// accepts Request.CustomTargets. A server checks it before sending
	// any, because an older probe ignores the field and refuses the ids.
	CapabilityCustomTargets = "custom_targets"
)

// Stage names where a probe stopped. The first group appears in a 200
// answer, the second in a 400 error.
type Stage string

const (
	StageOK        Stage = "ok"
	StageDecode    Stage = "decode"
	StageCreate    Stage = "create"
	StageServer    Stage = "server"
	StageHandshake Stage = "handshake"
	StageTarget    Stage = "target"
	StageTimeout   Stage = "timeout"

	StageRequest  Stage = "request"
	StagePolicy   Stage = "policy"
	StageInternal Stage = "internal"
)

// Request is the body of POST /v1/probe. Outbounds stay raw so the engine
// can decode them with the sing-box option registry, exactly as
// `sing-box check` does.
type Request struct {
	Engine          string            `json:"engine,omitempty"`
	Outbounds       []json.RawMessage `json:"outbounds"`
	Test            string            `json:"test"`
	Targets         []string          `json:"targets"`
	CustomTargets   []CustomTarget    `json:"custom_targets,omitempty"`
	Samples         int               `json:"samples"`
	UDP             bool              `json:"udp"`
	Throughput      bool              `json:"throughput"`
	ThroughputBytes int64             `json:"throughput_bytes"`
	TimeoutMS       int               `json:"timeout_ms"`
}

// CustomTarget is a target the operator saved in lattice-server. The server
// sends the definition of each saved target a request names in targets; the
// probe checks it again before use (policy.Parse), because a definition is
// a URL the probe would otherwise fetch on a caller's word.
type CustomTarget struct {
	ID           string `json:"id"`
	URL          string `json:"url"`
	Method       string `json:"method"`
	ExpectStatus string `json:"expect_status"`
	BodyContains string `json:"body_contains,omitempty"`
}

// Result is the answer to every completed probe, including one whose
// outbound failed.
type Result struct {
	Valid      bool           `json:"valid"`
	Stage      Stage          `json:"stage"`
	Error      string         `json:"error"`
	Server     Server         `json:"server"`
	Targets    []TargetResult `json:"targets"`
	Exit       *Exit          `json:"exit"`
	UDP        *UDP           `json:"udp"`
	Throughput *Throughput    `json:"throughput"`
	Engine     EngineInfo     `json:"engine"`
	TookMS     float64        `json:"took_ms"`

	// Types lists the outbound types of the request for logging. It never
	// carries anything the caller typed beyond the allowed type names.
	Types []string `json:"-"`
}

// Server is the plain reachability check of the first hop, made outside
// the proxy protocol.
type Server struct {
	Address   string  `json:"address"`
	Reachable bool    `json:"reachable"`
	RTTMS     float64 `json:"rtt_ms"`
	Network   string  `json:"network"`
}

// Dist summarises delay samples in milliseconds with one decimal.
type Dist struct {
	Min float64 `json:"min"`
	P50 float64 `json:"p50"`
	P90 float64 `json:"p90"`
}

type TargetResult struct {
	ID     string `json:"id"`
	OK     int    `json:"ok"`
	Of     int    `json:"of"`
	ColdMS Dist   `json:"cold_ms"`
	WarmMS Dist   `json:"warm_ms"`
	Status int    `json:"status"`
	Error  string `json:"error"`
	// BodyMatch is set for a target with a body needle once any response
	// arrived: true when at least one sample's body held the needle.
	BodyMatch *bool `json:"body_match,omitempty"`
}

type Exit struct {
	IP   string `json:"ip"`
	Loc  string `json:"loc"`
	Colo string `json:"colo"`
}

type UDP struct {
	OK    bool    `json:"ok"`
	RTTMS float64 `json:"rtt_ms"`
	Error string  `json:"error"`
}

type Throughput struct {
	Bytes   int64   `json:"bytes"`
	Seconds float64 `json:"seconds"`
	Mbps    float64 `json:"mbps"`
}

type EngineInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Health is the body of GET /v1/health.
type Health struct {
	ProbeVersion string `json:"probe_version"`
	Engine       string `json:"engine"`
	CoreVersion  string `json:"core_version"`
	UptimeS      int64  `json:"uptime_s"`
	Inflight     int64  `json:"inflight"`
	MaxInflight  int    `json:"max_inflight"`
	Targets      int    `json:"targets"`
	// Capabilities names optional features this probe supports, such as
	// CapabilityCustomTargets.
	Capabilities []string `json:"capabilities"`
}

// ErrorBody is the body of every non-200 answer.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Stage   Stage  `json:"stage"`
	Message string `json:"message"`
}

// RequestError is a refusal answered with 400 (or 429 for Busy).
type RequestError struct {
	Stage   Stage
	Message string
}

func (e *RequestError) Error() string { return string(e.Stage) + ": " + e.Message }

// Refuse builds a policy refusal.
func Refuse(message string) *RequestError {
	return &RequestError{Stage: StagePolicy, Message: message}
}

// Malformed builds a request-shape error.
func Malformed(message string) *RequestError {
	return &RequestError{Stage: StageRequest, Message: message}
}
