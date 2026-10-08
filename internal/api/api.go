// Package api serves the probe over HTTP/1.1 on a unix socket. It owns the
// request limits (body size, concurrency) and the log line; the engine owns
// everything about outbounds.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/policy"
	"github.com/LatticeNet/lattice-probe/internal/spec"
)

// Prober is what the API needs from an engine.
type Prober interface {
	Run(ctx context.Context, req *spec.Request) (*spec.Result, error)
	Targets() []spec.Target
	CoreVersion() string
}

// Server is the HTTP side of the probe.
type Server struct {
	prober   Prober
	log      *slog.Logger
	slots    chan struct{}
	inflight atomic.Int64
	started  time.Time
}

// New builds a Server allowing spec.MaxInflight probes at once.
func New(p Prober, log *slog.Logger) *Server {
	return &Server{prober: p, log: log, slots: make(chan struct{}, spec.MaxInflight), started: time.Now()}
}

// Handler routes the three endpoints.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/health", s.health)
	mux.HandleFunc("GET /v1/targets", s.targets)
	mux.HandleFunc("POST /v1/probe", s.probe)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/health", "/v1/targets", "/v1/probe":
			writeError(w, http.StatusMethodNotAllowed, spec.StageRequest, r.Method+" is not allowed on "+r.URL.Path)
		default:
			writeError(w, http.StatusNotFound, spec.StageRequest, "no such endpoint; the API is GET /v1/health, GET /v1/targets and POST /v1/probe")
		}
	})
	return mux
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, spec.Health{
		ProbeVersion: spec.Version,
		Engine:       spec.EngineName,
		CoreVersion:  s.prober.CoreVersion(),
		UptimeS:      int64(time.Since(s.started).Seconds()),
		Inflight:     s.inflight.Load(),
		MaxInflight:  spec.MaxInflight,
		Targets:      len(s.prober.Targets()),
	})
}

func (s *Server) targets(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, spec.TargetList{Targets: s.prober.Targets()})
}

func (s *Server) probe(w http.ResponseWriter, r *http.Request) {
	began := time.Now()
	id := requestID(r)
	w.Header().Set("X-Request-Id", id)

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, spec.MaxBodyBytes))
	if err != nil {
		var tooLarge *http.MaxBytesError
		msg := "could not read the request body"
		if errors.As(err, &tooLarge) {
			msg = "request body exceeds " + strconv.Itoa(spec.MaxBodyBytes) + " bytes"
		}
		s.logProbe(id, nil, spec.StageRequest, began)
		writeError(w, http.StatusBadRequest, spec.StageRequest, msg)
		return
	}
	var req spec.Request
	if err := json.Unmarshal(body, &req); err != nil {
		s.logProbe(id, nil, spec.StageRequest, began)
		writeError(w, http.StatusBadRequest, spec.StageRequest, "body is not a valid probe request: "+jsonProblem(err))
		return
	}
	types := requestTypes(&req)

	select {
	case s.slots <- struct{}{}:
	default:
		s.logProbe(id, types, "busy", began)
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, spec.StageRequest, "probe is busy: "+strconv.Itoa(spec.MaxInflight)+" probes are in flight; retry shortly")
		return
	}
	s.inflight.Add(1)
	defer func() {
		s.inflight.Add(-1)
		<-s.slots
	}()

	res, err := s.prober.Run(r.Context(), &req)
	if err != nil {
		var refusal *spec.RequestError
		if errors.As(err, &refusal) {
			s.logProbe(id, types, refusal.Stage, began)
			writeError(w, http.StatusBadRequest, refusal.Stage, refusal.Message)
			return
		}
		s.logProbe(id, types, spec.StageInternal, began)
		writeError(w, http.StatusInternalServerError, spec.StageInternal, "probe failed inside the engine")
		return
	}
	stage := res.Stage
	if errors.Is(r.Context().Err(), context.Canceled) {
		stage = "cancelled"
	}
	s.logProbe(id, res.Types, stage, began)
	writeJSON(w, http.StatusOK, res)
}

// logProbe writes the one line a probe leaves behind: request id, outbound
// types, stage and duration. Never the outbound, never an error text that
// could quote one.
func (s *Server) logProbe(id string, types []string, stage spec.Stage, began time.Time) {
	s.log.Info("probe",
		slog.String("request_id", id),
		slog.String("types", strings.Join(types, ",")),
		slog.String("stage", string(stage)),
		slog.Int64("duration_ms", time.Since(began).Milliseconds()),
	)
}

// requestTypes extracts the outbound types for the log line, keeping only
// names on the allow list so nothing a caller typed reaches the log.
func requestTypes(req *spec.Request) []string {
	types := make([]string, 0, len(req.Outbounds))
	for _, raw := range req.Outbounds {
		var head struct {
			Type string `json:"type"`
		}
		_ = json.Unmarshal(raw, &head)
		if policy.AllowedTypes[head.Type] {
			types = append(types, head.Type)
		} else {
			types = append(types, "other")
		}
	}
	return types
}

var callerID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// requestID reuses the caller's X-Request-Id when it is a plain token, so a
// probe can be matched with the server's audit record, and mints one
// otherwise.
func requestID(r *http.Request) string {
	if id := r.Header.Get("X-Request-Id"); callerID.MatchString(id) {
		return id
	}
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// jsonProblem describes a decode error without quoting the body.
func jsonProblem(err error) string {
	var syntax *json.SyntaxError
	var typeErr *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntax):
		return "invalid JSON at byte " + strconv.FormatInt(syntax.Offset, 10)
	case errors.As(err, &typeErr):
		field := typeErr.Field
		if field == "" {
			field = "body"
		}
		return field + " must be " + typeErr.Type.String()
	}
	return "invalid JSON"
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, stage spec.Stage, message string) {
	writeJSON(w, status, spec.ErrorBody{Error: spec.ErrorDetail{Stage: stage, Message: message}})
}
