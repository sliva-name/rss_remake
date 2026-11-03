// Package stand connects integration tests to the local dataguard-dev stand.
package stand

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
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
	_, file, _, _ := runtime.Caller(0)
	path := filepath.Join(filepath.Dir(file), "..", "..", "..", "deployments", "dev", ".env")
	handle, err := os.Open(filepath.Clean(path))
	if err != nil {
		t.Fatalf("stand is not configured, run make dev-up: %v", err)
	}
	defer func() { _ = handle.Close() }()

	values := map[string]string{}
	scanner := bufio.NewScanner(handle)
	for scanner.Scan() {
		if key, value, found := strings.Cut(scanner.Text(), "="); found {
			values[key] = value
		}
	}
	return values
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
