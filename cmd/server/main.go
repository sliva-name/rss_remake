// Command dataguard-server runs the central platform.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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
	"dataguard/internal/platform/retry"
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
	defaultMigrateWait    = "2m"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "dataguard-server:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: dataguard-server migrate|pki-init|rotate-policy-key|serve|ready")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch os.Args[1] {
	case "migrate":
		return migrateWhenReachable(ctx)
	case "pki-init":
		return pkiInit(os.Args[2:])
	case "rotate-policy-key":
		return rotatePolicyKey(os.Args[2:])
	case "serve":
		return serve(ctx)
	case "ready":
		return ready(ctx)
	default:
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

// migrateWhenReachable waits for the databases to accept connections. A database
// started next to it may still be initializing on a server other containers
// cannot reach. Only a refused or failed dial is retried: such a run applied
// nothing, and every step records what it applied, so repeating it is safe. Any
// other error stops at once.
func migrateWhenReachable(ctx context.Context) error {
	wait, err := time.ParseDuration(envOr("DG_MIGRATE_WAIT", defaultMigrateWait))
	if err != nil {
		return fmt.Errorf("DG_MIGRATE_WAIT: %w", err)
	}
	deadline := time.Now().Add(wait)
	for attempt := 0; ; attempt++ {
		err := migrate(ctx)
		var dial *net.OpError
		if err == nil || !errors.As(err, &dial) || dial.Op != "dial" || time.Now().After(deadline) {
			return err
		}
		fmt.Fprintln(os.Stderr, "dataguard-server: a database is not reachable yet, retrying")
		if !retry.Sleep(ctx, retry.Backoff{Base: time.Second, Max: 5 * time.Second}.Delay(attempt)) {
			return ctx.Err()
		}
	}
}

func migrate(ctx context.Context) error {
	dsn := mustPostgresDSN("DG_PG_MIGRATION_DSN", "DG_PG_MIGRATION_PASSWORD")
	if err := postgres.Migrate(ctx, dsn, migrations.Postgres, "postgres"); err != nil {
		return err
	}
	owner := clickhouse.Settings{
		Address: mustEnv("DG_CH_ADDR"), Database: mustEnv("DG_CH_DATABASE"),
		Username: mustEnv("DG_CH_MIGRATION_USER"), Password: mustSecret("DG_CH_MIGRATION_PASSWORD"),
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
	admin.User, admin.Password = mustEnv("DG_BROKER_ADMIN_USER"), mustSecret("DG_BROKER_ADMIN_PASSWORD")
	return broker.Ensure(ctx, admin, broker.Setup{
		Topic: runtime.Topic, Group: runtime.Group, Partitions: int32(partitions), Replication: int16(replication),
		Retention: retention, User: runtime.User, Password: runtime.Password,
	})
}

func brokerSettings() broker.Settings {
	return broker.Settings{
		Brokers: strings.Split(mustEnv("DG_BROKERS"), ","),
		Topic:   envOr("DG_BROKER_TOPIC", defaultTopic), Group: envOr("DG_BROKER_GROUP", defaultGroup),
		User: mustEnv("DG_BROKER_USER"), Password: mustSecret("DG_BROKER_PASSWORD"), CAFile: os.Getenv("DG_BROKER_CA_FILE"),
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
	keepExisting := flags.Bool("keep-existing", false, "keep an existing CA and keys, renewing only the server certificate when due")
	publicDirectory := flags.String("public-dir", "", "directory that receives a copy of the CA certificate for agents")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *directory == "" || *hosts == "" {
		return errors.New("--dir and --hosts are required")
	}
	hostList := strings.Split(*hosts, ",")
	if _, err := os.Stat(filepath.Join(*directory, pki.CAKeyFile)); !*keepExisting || err != nil {
		if err := pki.Bootstrap(*directory, hostList); err != nil {
			return err
		}
	} else if renewed, err := pki.EnsureServerCertificate(*directory, hostList, time.Now()); err != nil {
		return err
	} else if renewed {
		fmt.Fprintln(os.Stderr, "dataguard-server: server certificate issued anew")
	}
	if finished, err := pki.FinishPolicyKeyRotation(*directory); err != nil {
		return err
	} else if finished {
		fmt.Fprintln(os.Stderr, "dataguard-server: an interrupted policy key rotation was finished")
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

// rotatePolicyKey replaces the key that signs policies and source lists. Every
// server instance must restart afterwards to sign with the new key; agents take
// it with their next heartbeat (ADR-0014).
func rotatePolicyKey(args []string) error {
	flags := flag.NewFlagSet("rotate-policy-key", flag.ContinueOnError)
	directory := flags.String("dir", "", "the PKI directory of pki-init")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *directory == "" {
		return errors.New("--dir is required")
	}
	epoch, err := pki.RotatePolicyKey(*directory)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "dataguard-server: policy key epoch %d is current, restart every server instance\n", epoch)
	return nil
}

// apiCertificate is the dashboard's certificate, issued by the customer for the
// address people open. Without it the API speaks plain HTTP, which only suits
// a stand on loopback.
func apiCertificate() (*pki.FileCertificate, error) {
	certFile, keyFile := os.Getenv("DG_API_TLS_CERT_FILE"), os.Getenv("DG_API_TLS_KEY_FILE")
	switch {
	case certFile == "" && keyFile == "":
		return nil, nil
	case certFile == "" || keyFile == "":
		return nil, errors.New("DG_API_TLS_CERT_FILE and DG_API_TLS_KEY_FILE go together")
	}
	return pki.LoadFileCertificate(certFile, keyFile)
}

// readyClient reaches the local API. Over HTTPS it trusts exactly the
// configured certificate under its own name, so the check needs neither the
// customer's CA nor skipping verification.
func readyClient() (*http.Client, string, error) {
	certFile := os.Getenv("DG_API_TLS_CERT_FILE")
	if certFile == "" {
		return http.DefaultClient, "http", nil
	}
	pem, err := os.ReadFile(filepath.Clean(certFile)) //nolint:gosec // The operator chooses this path in the server's configuration.
	if err != nil {
		return nil, "", fmt.Errorf("DG_API_TLS_CERT_FILE: %w", err)
	}
	leaf, err := pki.ReadCertificate(certFile)
	if err != nil {
		return nil, "", fmt.Errorf("DG_API_TLS_CERT_FILE: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	serverName := ""
	switch {
	case len(leaf.DNSNames) > 0:
		serverName = leaf.DNSNames[0]
	case len(leaf.IPAddresses) > 0:
		serverName = leaf.IPAddresses[0].String()
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: serverName, MinVersion: tls.VersionTLS12}}
	return &http.Client{Transport: transport}, "https", nil
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
	client, scheme, err := readyClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, scheme+"://"+net.JoinHostPort(host, port)+"/readyz", http.NoBody)
	if err != nil {
		return err
	}
	response, err := client.Do(request)
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
	store, err := postgres.Open(ctx, mustPostgresDSN("DG_PG_DSN", "DG_PG_PASSWORD"))
	if err != nil {
		return err
	}
	defer store.Close()

	events, err := clickhouse.Open(ctx, clickhouse.Settings{
		Address: mustEnv("DG_CH_ADDR"), Database: mustEnv("DG_CH_DATABASE"),
		Username: mustEnv("DG_CH_USER"), Password: mustSecret("DG_CH_PASSWORD"),
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
	dashboardCertificate, err := apiCertificate()
	if err != nil {
		return err
	}
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
		return app.Serve(groupContext, application, app.ServeOptions{
			APIAddress: mustEnv("DG_API_ADDR"), APICertificate: dashboardCertificate,
			AgentAddress: mustEnv("DG_AGENT_ADDR"), MetricsAddress: os.Getenv("DG_METRICS_ADDR"),
		}, metrics, logger)
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
