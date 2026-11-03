// Command dataguard-agent runs inside the customer's network.
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
	"path/filepath"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // log time zones are resolved by name, whatever the image provides

	"golang.org/x/sync/errgroup"

	"dataguard/internal/agent/center"
	"dataguard/internal/agent/config"
	"dataguard/internal/agent/identity"
	"dataguard/internal/agent/queue"
	"dataguard/internal/agent/runtime"
	"dataguard/internal/agent/sources"
	"dataguard/internal/agent/telemetry"
	"dataguard/internal/platform/safelog"
)

const (
	version        = "0.1.0"
	metricsTimeout = 10 * time.Second
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dataguard-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: dataguard-agent enroll|run --config FILE")
	}
	flags := flag.NewFlagSet(os.Args[1], flag.ContinueOnError)
	configPath := flags.String("config", "", "path to the agent configuration")
	tokenFile := flags.String("token-file", "", "file with the enrollment token")
	if err := flags.Parse(os.Args[2:]); err != nil {
		return err
	}
	settings, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch os.Args[1] {
	case "enroll":
		return enroll(ctx, settings, *tokenFile)
	case "run":
		return serve(ctx, settings)
	default:
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func enroll(ctx context.Context, settings *config.Config, tokenFile string) error {
	token, err := os.ReadFile(filepath.Clean(tokenFile)) //nolint:gosec // The operator chooses this path on the command line.
	if err != nil {
		return fmt.Errorf("read token: %w", err)
	}
	return runtime.Enroll(ctx, settings, strings.TrimSpace(string(token)), version)
}

func serve(ctx context.Context, settings *config.Config) error {
	logger := safelog.New(os.Stdout, slog.LevelInfo)
	store, err := identity.Open(settings.StateDir)
	if err != nil {
		return err
	}
	observer := telemetry.New()
	client, err := center.New(settings.Center.URL, settings.Center.CAFile, store, observer)
	if err != nil {
		return err
	}
	registry := sources.NewRegistry()
	defer func() { _ = registry.Close() }()
	sourceSync := &runtime.SourceSync{
		Registry: registry, Allowlist: settings.Allowlist(), Key: store.SealingKey(),
		TenantID: store.TenantID(), AgentID: store.AgentID(), Logger: logger,
	}
	// The last accepted list keeps sources served while the center is down.
	stored, err := store.LoadSources()
	if err != nil {
		return err
	}
	if stored != nil {
		sourceSync.ApplySources(ctx, stored)
	}

	events, err := queue.Open(settings.StateDir, uint64(settings.QueueCap))
	if err != nil {
		return err
	}
	defer func() { _ = events.Close() }()
	verifier, err := runtime.NewContextVerifier(settings.Applications)
	if err != nil {
		return err
	}

	discovery := runtime.NewDiscovery(client, registry, 0, logger)
	policy, err := store.LoadPolicy()
	if err != nil {
		return err
	}
	if policy != nil {
		discovery.ApplyPolicy(policy)
	}
	audit := runtime.NewAudit(client, registry, events, verifier, logger, observer)
	control := runtime.NewControl(runtime.Options{
		Client: client, Identity: store, Prober: registry, Sources: sourceSync, Health: audit,
		Policies: discovery, Version: version, Logger: logger, Metrics: observer,
	})
	observer.Watch(audit, registry, store)

	logger.Info("agent started", "agent_id", store.AgentID().String(), "version", version)
	group, groupContext := errgroup.WithContext(ctx)
	group.Go(func() error { control.Run(groupContext); return nil })
	group.Go(func() error { discovery.Run(groupContext); return nil })
	group.Go(func() error { audit.Run(groupContext); return nil })
	if settings.Metrics.Address != "" {
		group.Go(func() error { return serveMetrics(groupContext, settings.Metrics.Address, observer, logger) })
	}
	return group.Wait()
}

// serveMetrics answers GET /metrics and nothing else. The port is read-only: no
// request changes the agent or reaches a source.
func serveMetrics(ctx context.Context, address string, observer *telemetry.Agent, logger *slog.Logger) error {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", observer.Handler())
	server := &http.Server{Addr: address, Handler: mux, ReadHeaderTimeout: metricsTimeout, WriteTimeout: metricsTimeout}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.WithoutCancel(ctx), metricsTimeout)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	logger.Info("metrics listening", "address", address)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve metrics: %w", err)
	}
	return nil
}
