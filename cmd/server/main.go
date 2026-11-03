// Command dataguard-server runs the central platform.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sync/errgroup"

	"dataguard/internal/platform/pki"
	"dataguard/internal/platform/safelog"
	"dataguard/internal/server/api"
	"dataguard/internal/server/app"
	"dataguard/internal/server/broker"
	"dataguard/internal/server/storage/clickhouse"
	"dataguard/internal/server/storage/postgres"
	"dataguard/internal/server/telemetry"
	"dataguard/migrations"
)

const (
	defaultCertificateTTL = 7 * 24 * time.Hour
	defaultTopic          = "dataguard.audit-events"
	defaultGroup          = "dataguard-ingest"
	defaultPartitions     = "12"
	defaultRetention      = "168h"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dataguard-server:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: dataguard-server migrate|pki-init|serve|ready")
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
	case "ready":
		return ready(ctx)
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
	if err := clickhouse.Migrate(ctx, owner, mustEnv("DG_CH_USER"), migrations.ClickHouse, "clickhouse"); err != nil {
		return err
	}
	return migrateBroker(ctx)
}

// migrateBroker prepares the topic and the server's broker account. Replication
// has no default: one copy is fine for a stand and wrong for an installation.
func migrateBroker(ctx context.Context) error {
	replication, err := strconv.ParseInt(mustEnv("DG_BROKER_REPLICATION"), 10, 16)
	if err != nil {
		return fmt.Errorf("DG_BROKER_REPLICATION: %w", err)
	}
	partitions, err := strconv.ParseInt(envOr("DG_BROKER_PARTITIONS", defaultPartitions), 10, 32)
	if err != nil {
		return fmt.Errorf("DG_BROKER_PARTITIONS: %w", err)
	}
	retention, err := time.ParseDuration(envOr("DG_BROKER_RETENTION", defaultRetention))
	if err != nil {
		return fmt.Errorf("DG_BROKER_RETENTION: %w", err)
	}
	runtime := brokerSettings()
	admin := runtime
	admin.User, admin.Password = mustEnv("DG_BROKER_ADMIN_USER"), mustEnv("DG_BROKER_ADMIN_PASSWORD")
	return broker.Ensure(ctx, admin, broker.Setup{
		Topic: runtime.Topic, Group: runtime.Group, Partitions: int32(partitions), Replication: int16(replication),
		Retention: retention, User: runtime.User, Password: runtime.Password,
	})
}

func brokerSettings() broker.Settings {
	return broker.Settings{
		Brokers: strings.Split(mustEnv("DG_BROKERS"), ","),
		Topic:   envOr("DG_BROKER_TOPIC", defaultTopic), Group: envOr("DG_BROKER_GROUP", defaultGroup),
		User: mustEnv("DG_BROKER_USER"), Password: mustEnv("DG_BROKER_PASSWORD"), CAFile: os.Getenv("DG_BROKER_CA_FILE"),
	}
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func pkiInit(args []string) error {
	flags := flag.NewFlagSet("pki-init", flag.ContinueOnError)
	directory := flags.String("dir", "", "directory for the CA, server and policy keys")
	hosts := flags.String("hosts", "", "comma-separated server names and addresses")
	keepExisting := flags.Bool("keep-existing", false, "succeed without changes if the CA already exists")
	publicDirectory := flags.String("public-dir", "", "directory that receives a copy of the CA certificate for agents")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *directory == "" || *hosts == "" {
		return errors.New("--dir and --hosts are required")
	}
	if _, err := os.Stat(filepath.Join(*directory, pki.CAKeyFile)); !*keepExisting || err != nil {
		if err := pki.Bootstrap(*directory, strings.Split(*hosts, ",")); err != nil {
			return err
		}
	}
	if *publicDirectory == "" {
		return nil
	}
	certificate, err := os.ReadFile(filepath.Join(filepath.Clean(*directory), pki.CACertFile))
	if err != nil {
		return fmt.Errorf("read ca certificate: %w", err)
	}
	//nolint:gosec // The CA certificate is public; agents running as any user must read it.
	return os.WriteFile(filepath.Join(filepath.Clean(*publicDirectory), pki.CACertFile), certificate, 0o644)
}

// ready asks the local API for readiness. It exists because the image has no
// shell or HTTP client for a container healthcheck.
func ready(ctx context.Context) error {
	host, port, err := net.SplitHostPort(mustEnv("DG_API_ADDR"))
	if err != nil {
		return fmt.Errorf("DG_API_ADDR: %w", err)
	}
	if host == "" {
		host = "127.0.0.1"
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+net.JoinHostPort(host, port)+"/readyz", http.NoBody)
	if err != nil {
		return err
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return err
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("not ready: %d", response.StatusCode)
	}
	return nil
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
	authenticator, err := api.NewOIDCAuthenticator(ctx, issuer, os.Getenv("DG_OIDC_DISCOVERY_URL"), clientID)
	if err != nil {
		return err
	}
	settings := brokerSettings()
	publisher, err := broker.NewPublisher(settings)
	if err != nil {
		return err
	}
	defer publisher.Close()

	pkiDirectory := mustEnv("DG_PKI_DIR")
	metrics := telemetry.New()
	application, err := app.Build(app.Options{
		Store: store, Events: events, Broker: publisher, PKIDirectory: pkiDirectory, CertificateTTL: defaultCertificateTTL,
		Authenticator: authenticator, Logger: logger,
		OIDCIssuer: issuer, OIDCClientID: clientID, WebDirectory: os.Getenv("DG_WEB_DIR"), Metrics: metrics,
	})
	if err != nil {
		return err
	}
	consumer := broker.NewConsumer(settings, application.Events.Store, metrics, logger)
	metrics.WatchLag(consumer.Lag)
	logger.Info("server started")
	group, groupContext := errgroup.WithContext(ctx)
	group.Go(func() error { consumer.Run(groupContext); return nil })
	group.Go(func() error {
		return app.Serve(groupContext, application, mustEnv("DG_API_ADDR"), mustEnv("DG_AGENT_ADDR"), os.Getenv("DG_METRICS_ADDR"), pkiDirectory, metrics)
	})
	return group.Wait()
}

func mustEnv(name string) string {
	value := os.Getenv(name)
	if value == "" {
		fmt.Fprintf(os.Stderr, "dataguard-server: %s is required\n", name)
		os.Exit(1)
	}
	return value
}
