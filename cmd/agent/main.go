// Command dataguard-agent runs inside the customer's network.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sync/errgroup"

	"dataguard/internal/agent/center"
	"dataguard/internal/agent/config"
	"dataguard/internal/agent/identity"
	"dataguard/internal/agent/runtime"
	"dataguard/internal/agent/sources"
	"dataguard/internal/platform/safelog"
)

const version = "0.1.0"

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
	client, err := center.New(settings.Center.URL, settings.Center.CAFile, store)
	if err != nil {
		return err
	}
	registry, err := sources.Open(settings.Sources)
	if err != nil {
		return err
	}
	defer func() { _ = registry.Close() }()

	discovery := runtime.NewDiscovery(client, registry, 0, logger)
	policy, err := store.LoadPolicy()
	if err != nil {
		return err
	}
	if policy != nil {
		discovery.ApplyPolicy(policy)
	}
	control := runtime.NewControl(runtime.Options{
		Client: client, Identity: store, Prober: registry, Assignments: registry,
		Policies: discovery, Version: version, Logger: logger,
	})

	logger.Info("agent started", "agent_id", store.AgentID().String(), "version", version)
	group, groupContext := errgroup.WithContext(ctx)
	group.Go(func() error { control.Run(groupContext); return nil })
	group.Go(func() error { discovery.Run(groupContext); return nil })
	return group.Wait()
}
