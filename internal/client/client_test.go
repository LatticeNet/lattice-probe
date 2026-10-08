package client

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/api"
	"github.com/LatticeNet/lattice-probe/internal/spec"
)

type refusingProber struct{}

func (refusingProber) Run(context.Context, *spec.Request) (*spec.Result, error) {
	return nil, spec.Refuse("address refused: 10.0.0.1, which is private")
}
func (refusingProber) Targets() []spec.Target { return spec.DefaultTargets() }
func (refusingProber) CoreVersion() string    { return "1.13.19" }

func TestHealthAndRefusalOverTheSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "probe.sock")
	ln, err := api.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: api.New(refusingProber{}, slog.New(slog.NewJSONHandler(io.Discard, nil))).Handler(), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	defer srv.Close()

	c := New(path, 3*time.Second)
	h, err := c.Health()
	if err != nil || h.Engine != "sing-box" || h.MaxInflight != spec.MaxInflight {
		t.Fatalf("health %+v %v", h, err)
	}
	_, err = c.Probe(&spec.Request{})
	var refusal *spec.RequestError
	if !errors.As(err, &refusal) || refusal.Stage != spec.StagePolicy {
		t.Fatalf("probe: %v, want a policy refusal", err)
	}
	if _, err := New(filepath.Join(dir, "missing.sock"), time.Second).Health(); err == nil {
		t.Error("health succeeded against a missing socket")
	}
}
