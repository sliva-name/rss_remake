// Package stand connects integration tests to the local dataguard-dev stand.
package stand

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"dataguard/internal/server/broker"
	"dataguard/internal/server/storage/clickhouse"
	"dataguard/internal/server/storage/postgres"
	"dataguard/migrations"
)

const centerPostgres = "127.0.0.1:25442"

// Env returns the stand's generated secrets.
func Env(t *testing.T) map[string]string {
	t.Helper()
	values, err := ReadEnv()
	if err != nil {
		t.Fatal(err)
	}
	return values
}

// ReadEnv is Env outside a test.
func ReadEnv() (map[string]string, error) {
	handle, err := os.Open(filepath.Clean(filepath.Join(DevDirectory(), ".env")))
	if err != nil {
		return nil, fmt.Errorf("stand is not configured, run make dev-up: %w", err)
	}
	defer func() { _ = handle.Close() }()

	values := map[string]string{}
	scanner := bufio.NewScanner(handle)
	for scanner.Scan() {
		if key, value, found := strings.Cut(scanner.Text(), "="); found {
			values[key] = value
		}
	}
	return values, scanner.Err()
}

// DevDirectory is deployments/dev of this repository.
func DevDirectory() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "deployments", "dev")
}

func centerDSN(user, password, database string) string {
	dsn := url.URL{
		Scheme: "postgres", User: url.UserPassword(user, password), Host: centerPostgres,
		Path: "/" + database, RawQuery: "sslmode=disable",
	}
	return dsn.String()
}

// CenterDatabase creates a private migrated database, so tests stay independent
// of each other and of any previous run, and returns its owner and runtime DSNs.
func CenterDatabase(t *testing.T) (ownerDSN, runtimeDSN string) {
	t.Helper()
	ctx := t.Context()
	env := Env(t)
	admin := centerDSN("dg_owner", env["CENTER_PG_ADMIN_PASSWORD"], "dataguard")

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	name := "test_" + hex.EncodeToString(suffix)
	connection, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatalf("connect to stand: %v", err)
	}
	defer func() { _ = connection.Close(ctx) }()
	if _, err := connection.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, pgx.Identifier{name}.Sanitize())); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() { dropDatabase(admin, name) })

	ownerDSN = centerDSN("dg_owner", env["CENTER_PG_ADMIN_PASSWORD"], name)
	if err := postgres.Migrate(ctx, ownerDSN, migrations.Postgres, "postgres"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return ownerDSN, centerDSN("dg_runtime", env["CENTER_PG_APP_PASSWORD"], name)
}

const centerClickHouse = "127.0.0.1:25900"

const centerBroker = "127.0.0.1:25092"

// CenterBroker creates a private topic and consumer group, open to the stand's
// server account only, and returns the server's settings for them.
func CenterBroker(t *testing.T) broker.Settings {
	t.Helper()
	env := Env(t)
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	name := "test_" + hex.EncodeToString(suffix)
	server := broker.Settings{
		Brokers: []string{centerBroker}, Topic: name, Group: name,
		User: "dg_broker_app", Password: env["CENTER_BROKER_APP_PASSWORD"],
	}
	admin := server
	admin.User, admin.Password = "dg_broker_admin", env["CENTER_BROKER_ADMIN_PASSWORD"]
	setup := broker.Setup{
		Topic: name, Group: name, Partitions: 3, Replication: 1, Retention: time.Hour,
		User: server.User, Password: server.Password,
	}
	if err := broker.Ensure(t.Context(), admin, setup); err != nil {
		t.Fatalf("prepare broker topic: %v", err)
	}
	// The test's context is already cancelled when cleanups run.
	t.Cleanup(func() { _ = broker.Remove(context.WithoutCancel(t.Context()), admin, setup) })
	return server
}

// CenterEvents creates a private migrated ClickHouse database and returns runtime
// settings.
func CenterEvents(t *testing.T) clickhouse.Settings {
	t.Helper()
	owner, runtime := EmptyCenterEvents(t)
	if err := clickhouse.Migrate(t.Context(), owner, runtime.Username, migrations.ClickHouse, "clickhouse"); err != nil {
		t.Fatalf("migrate clickhouse: %v", err)
	}
	return runtime
}

// EmptyCenterEvents creates a private ClickHouse database without migrating it and
// returns the schema owner's and the runtime user's settings.
func EmptyCenterEvents(t *testing.T) (owner, runtime clickhouse.Settings) {
	t.Helper()
	env := Env(t)
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	name := "test_" + hex.EncodeToString(suffix)
	admin := clickhouse.Settings{Address: centerClickHouse, Database: "default", Username: "dg_ch_admin", Password: env["CENTER_CH_ADMIN_PASSWORD"]}
	if err := clickhouse.ExecAdmin(t.Context(), admin, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create clickhouse database: %v", err)
	}
	t.Cleanup(func() {
		ctx := context.WithoutCancel(t.Context())
		// Row policies outlive the database they guard, so they are dropped first.
		_ = clickhouse.ExecAdmin(ctx, admin, "DROP ROW POLICY IF EXISTS tenant_isolation ON "+name+".audit_events")
		_ = clickhouse.ExecAdmin(ctx, admin, "DROP DATABASE "+name)
	})
	owner = admin
	owner.Database = name
	return owner, clickhouse.Settings{Address: centerClickHouse, Database: name, Username: "dg_ch_app", Password: env["CENTER_CH_APP_PASSWORD"]}
}

func dropDatabase(admin, name string) {
	ctx := context.Background()
	connection, err := pgx.Connect(ctx, admin)
	if err != nil {
		return
	}
	defer func() { _ = connection.Close(ctx) }()
	_, _ = connection.Exec(ctx, fmt.Sprintf(`DROP DATABASE %s WITH (FORCE)`, pgx.Identifier{name}.Sanitize()))
}

// ApplicationKey is the signing key of the stand's demo application "crm",
// created by scripts/dev-env.sh; the agent container has its public half.
func ApplicationKey() (ed25519.PrivateKey, error) {
	encoded, err := os.ReadFile(filepath.Clean(filepath.Join(DevDirectory(), ".state", "apps", "crm.seed")))
	if err != nil {
		return nil, fmt.Errorf("application key is missing, run make dev-up: %w", err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("crm.seed is not a base64 ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}
