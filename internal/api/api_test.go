package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/engine"
	"github.com/LatticeNet/lattice-probe/internal/policy"
	"github.com/LatticeNet/lattice-probe/internal/spec"
	"github.com/LatticeNet/lattice-probe/internal/testkit"
)

// blockingProber holds every probe until released, to fill the slots.
type blockingProber struct {
	started chan struct{}
	release chan struct{}
}

func (b *blockingProber) Run(ctx context.Context, _ *spec.Request) (*spec.Result, error) {
	b.started <- struct{}{}
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return &spec.Result{Stage: spec.StageOK, Targets: []spec.TargetResult{}}, nil
}
func (b *blockingProber) Targets() []spec.Target { return spec.DefaultTargets() }
func (b *blockingProber) CoreVersion() string    { return "1.13.19" }

const minimalBody = `{"outbounds":[{"type":"shadowsocks","tag":"a","server":"1.1.1.1","server_port":1}]}`

func post(t *testing.T, h http.Handler, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/probe", strings.NewReader(body)))
	return rec
}

func decodeError(t *testing.T, rec *httptest.ResponseRecorder) spec.ErrorDetail {
	t.Helper()
	var body spec.ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("error body %q: %v", rec.Body.String(), err)
	}
	return body.Error
}

func TestTooManyInflight(t *testing.T) {
	p := &blockingProber{started: make(chan struct{}, spec.MaxInflight), release: make(chan struct{})}
	s := New(p, slog.New(slog.NewJSONHandler(io.Discard, nil)))
	h := s.Handler()
	var wg sync.WaitGroup
	for range spec.MaxInflight {
		wg.Go(func() {
			if rec := post(t, h, minimalBody); rec.Code != http.StatusOK {
				t.Errorf("held probe answered %d", rec.Code)
			}
		})
	}
	for range spec.MaxInflight {
		<-p.started
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	var health spec.Health
	_ = json.Unmarshal(rec.Body.Bytes(), &health)
	if health.Inflight != spec.MaxInflight || health.MaxInflight != spec.MaxInflight {
		t.Errorf("health while full: %+v", health)
	}

	rec = post(t, h, minimalBody)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("probe %d answered %d, want 429", spec.MaxInflight+1, rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}
	if e := decodeError(t, rec); e.Message == "" {
		t.Error("429 without a message")
	}
	close(p.release)
	wg.Wait()
	if rec := post(t, h, minimalBody); rec.Code != http.StatusOK {
		t.Errorf("after release a probe answered %d", rec.Code)
	}
}

func TestRequestErrors(t *testing.T) {
	p := &blockingProber{started: make(chan struct{}, 1), release: make(chan struct{})}
	close(p.release)
	h := New(p, slog.New(slog.NewJSONHandler(io.Discard, nil))).Handler()

	big := `{"outbounds":[{"type":"shadowsocks","tag":"a","server":"1.1.1.1","server_port":1,"pad":"` + strings.Repeat("x", spec.MaxBodyBytes) + `"}]}`
	cases := map[string]string{
		"oversize body": big,
		"not json":      "outbounds: yes",
		"wrong types":   `{"outbounds":"x"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			rec := post(t, h, body)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("answered %d, want 400", rec.Code)
			}
			if e := decodeError(t, rec); e.Stage != spec.StageRequest || e.Message == "" {
				t.Errorf("error %+v", e)
			}
		})
	}

	for path, want := range map[string]int{"/v1/nope": http.StatusNotFound, "/v1/health": http.StatusMethodNotAllowed} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader("{}")))
		if rec.Code != want {
			t.Errorf("POST %s answered %d, want %d", path, rec.Code, want)
		}
	}
}

func TestHealthAndTargets(t *testing.T) {
	p := &blockingProber{}
	h := New(p, slog.New(slog.NewJSONHandler(io.Discard, nil))).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	var health map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"probe_version", "engine", "core_version", "uptime_s", "inflight", "max_inflight", "targets"} {
		if _, ok := health[key]; !ok {
			t.Errorf("health lacks %s: %v", key, health)
		}
	}
	if health["engine"] != "sing-box" || health["max_inflight"] != float64(32) || health["targets"] != float64(3) {
		t.Errorf("health %v", health)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/targets", nil))
	var list spec.TargetList
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	if len(list.Targets) != 3 || list.Targets[0].ID != "gstatic-204" || list.Targets[0].Expect != 204 {
		t.Errorf("targets %+v", list.Targets)
	}
}

// TestLogsNeverCarryCredentials runs real probes that pass, fail on a
// wrong password, fail to decode and are refused, and checks that neither
// the log nor any error text the API returns contains a credential.
func TestLogsNeverCarryCredentials(t *testing.T) {
	lab, err := testkit.Start()
	if err != nil {
		t.Fatal(err)
	}
	defer lab.Close()
	eng, err := engine.New(engine.Config{
		Targets:       lab.Targets(),
		Policy:        &policy.Policy{Allow: testkit.LoopbackOnly},
		TraceURL:      lab.TraceURL(),
		DNSServer:     lab.DNSAddr,
		SampleTimeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer eng.Close()
	var logs bytes.Buffer
	h := New(eng, slog.New(slog.NewJSONHandler(&logs, nil))).Handler()

	body := func(ob map[string]any) string {
		b, _ := json.Marshal(map[string]any{"outbounds": []any{ob}, "targets": []string{"lab-204"}, "samples": 1})
		return string(b)
	}
	secretUUID := "SECRET-not-a-uuid-" + lab.Password
	badUUID := lab.Outbound("vmess", "", "line")
	badUUID["uuid"] = secretUUID
	private := lab.Outbound("trojan", "", "line")
	private["server"] = "10.9.8.7"

	answers := []string{
		post(t, h, body(lab.Outbound("trojan", "", "line"))).Body.String(),
		post(t, h, body(lab.Outbound("trojan", "wrong", "line"))).Body.String(),
		post(t, h, body(lab.Outbound("hysteria2", "wrong", "line"))).Body.String(),
		post(t, h, body(badUUID)).Body.String(),
		post(t, h, body(private)).Body.String(),
	}
	secrets := append(lab.Secrets(), secretUUID)
	for _, secret := range secrets {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("log contains a credential: %s", logs.String())
		}
		for i, a := range answers {
			if strings.Contains(a, secret) {
				t.Errorf("answer %d echoes a credential: %s", i, a)
			}
		}
	}
	lines := strings.Split(strings.TrimSpace(logs.String()), "\n")
	if len(lines) != len(answers) {
		t.Fatalf("%d log lines for %d probes:\n%s", len(lines), len(answers), logs.String())
	}
	for _, line := range lines {
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		for key := range entry {
			switch key {
			case "time", "level", "msg", "request_id", "types", "stage", "duration_ms":
			default:
				t.Errorf("log line carries an unexpected field %q: %s", key, line)
			}
		}
	}
	if !strings.Contains(answers[0], `"stage":"ok"`) || !strings.Contains(answers[1], `"stage":"handshake"`) || !strings.Contains(answers[4], `"stage":"policy"`) {
		t.Errorf("unexpected answers:\n%s", strings.Join(answers, "\n"))
	}
}

func TestListen(t *testing.T) {
	dir, err := os.MkdirTemp("", "probe")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "probe.sock")

	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if mode := fi.Mode().Perm(); mode != SocketMode {
		t.Errorf("socket mode %o, want %o", mode, SocketMode)
	}
	if _, err := Listen(path); err == nil {
		t.Error("a second listener took over a live socket")
	}
	srv := &http.Server{Handler: New(&blockingProber{}, slog.New(slog.NewJSONHandler(io.Discard, nil))).Handler(), ReadHeaderTimeout: time.Second}
	go func() { _ = srv.Serve(ln) }()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}}}
	resp, err := client.Get("http://probe/v1/health")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health over the socket answered %d", resp.StatusCode)
	}
	srv.Close()

	// A socket file left by a crash is replaced; a regular file is not.
	stale, err := net.Listen("unix", path)
	if err == nil {
		stale.(*net.UnixListener).SetUnlinkOnClose(false)
		stale.Close()
	}
	ln, err = Listen(path)
	if err != nil {
		t.Fatalf("stale socket not replaced: %v", err)
	}
	ln.Close()
	regular := filepath.Join(dir, "file")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(regular); err == nil {
		t.Error("Listen replaced a regular file")
	}
}
