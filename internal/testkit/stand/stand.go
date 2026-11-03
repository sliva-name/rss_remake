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

	"github.com/jackc/pgx/v5"

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
	ctx := context.Background()
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

// CenterEvents creates a private migrated ClickHouse database and returns runtime
// settings.
func CenterEvents(t *testing.T) clickhouse.Settings {
	t.Helper()
	ctx := context.Background()
	env := Env(t)
	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatal(err)
	}
	name := "test_" + hex.EncodeToString(suffix)
	admin := clickhouse.Settings{Address: centerClickHouse, Database: "default", Username: "dg_ch_admin", Password: env["CENTER_CH_ADMIN_PASSWORD"]}
	if err := clickhouse.ExecAdmin(ctx, admin, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create clickhouse database: %v", err)
	}
	t.Cleanup(func() { _ = clickhouse.ExecAdmin(context.Background(), admin, "DROP DATABASE "+name) })
	owner := admin
	owner.Database = name
	if err := clickhouse.Migrate(ctx, owner, "dg_ch_app", migrations.ClickHouse, "clickhouse"); err != nil {
		t.Fatalf("migrate clickhouse: %v", err)
	}
	return clickhouse.Settings{Address: centerClickHouse, Database: name, Username: "dg_ch_app", Password: env["CENTER_CH_APP_PASSWORD"]}
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
