// Command lattice-probe is the long-lived outbound probe daemon. It runs
// one sing-box instance, serves the probe API on a unix socket, and never
// logs an outbound or a credential.
//
// Environment:
//
//	LATTICE_PROBE_SOCKET          socket path (default /run/lattice-probe/probe.sock)
//	LATTICE_PROBE_TARGETS_FILE    JSON {"targets":[...]} replacing the built-in targets
//	LATTICE_PROBE_ALLOW_PREFIXES  comma-separated CIDRs exempt from the address policy (default none)
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/LatticeNet/lattice-probe/internal/api"
	"github.com/LatticeNet/lattice-probe/internal/client"
	"github.com/LatticeNet/lattice-probe/internal/engine"
	"github.com/LatticeNet/lattice-probe/internal/policy"
	"github.com/LatticeNet/lattice-probe/internal/spec"
)

func main() {
	showVersion := flag.Bool("version", false, "print the version and exit")
	health := flag.Bool("health", false, "check the daemon serving LATTICE_PROBE_SOCKET and exit; the container health check")
	flag.Parse()
	if *showVersion {
		fmt.Println("lattice-probe", spec.Version)
		return
	}
	if *health {
		if _, err := client.New(socketPath(), 3*time.Second).Health(); err != nil {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
		return
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := serve(log); err != nil {
		log.Error("exit", slog.String("error", err.Error()))
		os.Exit(1)
	}
}

func socketPath() string {
	if socket := os.Getenv("LATTICE_PROBE_SOCKET"); socket != "" {
		return socket
	}
	return spec.DefaultSocket
}

func serve(log *slog.Logger) error {
	socket := socketPath()
	targets, err := spec.LoadTargets(os.Getenv("LATTICE_PROBE_TARGETS_FILE"))
	if err != nil {
		return err
	}
	allow, err := policy.ParsePrefixes(os.Getenv("LATTICE_PROBE_ALLOW_PREFIXES"))
	if err != nil {
		return err
	}
	eng, err := engine.New(engine.Config{Targets: targets, Policy: &policy.Policy{Allow: allow}})
	if err != nil {
		return err
	}
	defer eng.Close()

	ln, err := api.Listen(socket)
	if err != nil {
		return err
	}
	srv := &http.Server{
		Handler:           api.New(eng, log).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		// The longest probe is 30 s; the server side waits 35 s.
		WriteTimeout:   45 * time.Second,
		IdleTimeout:    2 * time.Minute,
		MaxHeaderBytes: 16 << 10,
		ErrorLog:       slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	allowed := make([]string, len(allow))
	for i, p := range allow {
		allowed[i] = p.String()
	}
	log.Info("ready",
		slog.String("socket", socket),
		slog.String("probe_version", spec.Version),
		slog.String("core_version", eng.CoreVersion()),
		slog.Int("targets", len(targets)),
		slog.Int("max_inflight", spec.MaxInflight),
		slog.String("allow_prefixes", strings.Join(allowed, ",")),
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case err := <-errc:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		log.Info("shutting down")
		shutdown, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdown); err != nil {
			return err
		}
	}
	return nil
}
