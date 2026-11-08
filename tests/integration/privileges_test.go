//go:build integration

package integration_test

import (
	"database/sql"
	"fmt"
	"net/url"
	"testing"

	"github.com/go-sql-driver/mysql"

	"dataguard/internal/testkit/seed"
	"dataguard/internal/testkit/stand"
	"dataguard/internal/testkit/synthetic"
)

// scannerConnection logs in with the credentials the agent is configured with.
func scannerConnection(t *testing.T, source stand.Source) *sql.DB {
	t.Helper()
	password := source.Config.Password
	config := source.Config
	var driver, dsn string
	switch source.Dialect.Name {
	case "postgresql":
		driver = "pgx"
		dsn = (&url.URL{Scheme: "postgres", User: url.UserPassword(config.Username, password),
			Host: fmt.Sprintf("%s:%d", config.Host, config.Port), Path: "/" + config.Database, RawQuery: "sslmode=disable"}).String()
	case "mysql", "mariadb":
		settings := mysql.NewConfig()
		settings.User, settings.Passwd, settings.Net = config.Username, password, "tcp"
		settings.Addr, settings.DBName, settings.TLSConfig = fmt.Sprintf("%s:%d", config.Host, config.Port), config.Database, "false"
		driver, dsn = "mysql", settings.FormatDSN()
	case "mssql":
		query := url.Values{"database": {config.Database}, "encrypt": {"true"}, "TrustServerCertificate": {"true"}}
		driver = "sqlserver"
		dsn = (&url.URL{Scheme: "sqlserver", User: url.UserPassword(config.Username, password),
			Host: fmt.Sprintf("%s:%d", config.Host, config.Port), RawQuery: query.Encode()}).String()
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestScannerAccountCannotChangeData proves the agent's own login is read-only in
// the stand, independent of the read-only transactions the connector also uses.
func TestScannerAccountCannotChangeData(t *testing.T) {
	ctx := t.Context()
	for _, source := range stand.AllSources(t) {
		t.Run(source.Dialect.Name, func(t *testing.T) {
			if err := seed.Tables(ctx, source.Admin, source.Dialect, 2, synthetic.New(1)); err != nil {
				t.Fatal(err)
			}
			scanner := scannerConnection(t, source)
			var rows int
			if err := scanner.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+seed.Users).Scan(&rows); err != nil || rows != 2 {
				t.Fatalf("the scanner must read: %d, %v", rows, err)
			}
			for _, statement := range []string{
				`UPDATE ` + seed.Users + ` SET status = 'x'`,
				`DELETE FROM ` + seed.Users,
				`CREATE TABLE dg_scanner_probe (id int)`,
			} {
				if _, err := scanner.ExecContext(ctx, statement); err == nil {
					t.Errorf("scanner account was allowed: %s", statement)
				}
			}
		})
	}
}
