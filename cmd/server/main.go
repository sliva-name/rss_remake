// Command dataguard-server runs the central platform.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"dataguard/internal/platform/pki"
	"dataguard/internal/platform/safelog"
	"dataguard/internal/server/api"
	"dataguard/internal/server/app"
	"dataguard/internal/server/storage/clickhouse"
	"dataguard/internal/server/storage/postgres"
	"dataguard/migrations"
)

const defaultCertificateTTL = 7 * 24 * time.Hour

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dataguard-server:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: dataguard-server migrate|pki-init|serve")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch os.Args[1] {
	case "migrate":
		return migrate(ctx)
	case "pki-init":
		return pkiInit(os.Args[2:])
	case "serve":
		return serve(ctx)
	default:
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func migrate(ctx context.Context) error {
	if err := postgres.Migrate(ctx, mustEnv("DG_PG_MIGRATION_DSN"), migrations.Postgres, "postgres"); err != nil {
		return err
	}
	owner := clickhouse.Settings{
		Address: mustEnv("DG_CH_ADDR"), Database: mustEnv("DG_CH_DATABASE"),
		Username: mustEnv("DG_CH_MIGRATION_USER"), Password: mustEnv("DG_CH_MIGRATION_PASSWORD"),
	}
	return clickhouse.Migrate(ctx, owner, mustEnv("DG_CH_USER"), migrations.ClickHouse, "clickhouse")
}

func pkiInit(args []string) error {
	flags := flag.NewFlagSet("pki-init", flag.ContinueOnError)
	directory := flags.String("dir", "", "directory for the CA, server and policy keys")
	hosts := flags.String("hosts", "", "comma-separated server names and addresses")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *directory == "" || *hosts == "" {
		return errors.New("--dir and --hosts are required")
	}
	return pki.Bootstrap(*directory, strings.Split(*hosts, ","))
}

func serve(ctx context.Context) error {
	logger := safelog.New(os.Stdout, slog.LevelInfo)
	store, err := postgres.Open(ctx, mustEnv("DG_PG_DSN"))
	if err != nil {
		return err
	}
	defer store.Close()

	events, err := clickhouse.Open(ctx, clickhouse.Settings{
		Address: mustEnv("DG_CH_ADDR"), Database: mustEnv("DG_CH_DATABASE"),
		Username: mustEnv("DG_CH_USER"), Password: mustEnv("DG_CH_PASSWORD"),
	})
	if err != nil {
		return err
	}
	defer func() { _ = events.Close() }()

	issuer, clientID := mustEnv("DG_OIDC_ISSUER"), mustEnv("DG_OIDC_CLIENT_ID")
	authenticator, err := api.NewOIDCAuthenticator(ctx, issuer, clientID)
	if err != nil {
		return err
	}
	pkiDirectory := mustEnv("DG_PKI_DIR")
	application, err := app.Build(app.Options{
		Store: store, Events: events, PKIDirectory: pkiDirectory, CertificateTTL: defaultCertificateTTL,
		Authenticator: authenticator, Logger: logger,
		OIDCIssuer: issuer, OIDCClientID: clientID, WebDirectory: os.Getenv("DG_WEB_DIR"),
	})
	if err != nil {
		return err
	}
	logger.Info("server started")
	return app.Serve(ctx, application, mustEnv("DG_API_ADDR"), mustEnv("DG_AGENT_ADDR"), pkiDirectory)
}

func mustEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		fmt.Fprintf(os.Stderr, "dataguard-server: %s is required\n", name)
		os.Exit(1)
	}
	return value
}
