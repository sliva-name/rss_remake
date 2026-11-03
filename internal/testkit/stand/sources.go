package stand

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"  // registers the driver
	_ "github.com/microsoft/go-mssqldb" // registers the driver

	"dataguard/internal/agent/config"
	"dataguard/internal/testkit/seed"
)

// Host ports of the stand's source databases.
const (
	PostgresPort = 25432
	MySQLPort    = 25306
	MariaDBPort  = 25307
	MSSQLPort    = 25433
	host         = "127.0.0.1"
)

// Source bundles a stand database with everything a test needs for it.
type Source struct {
	Config  config.Source
	Dialect seed.Dialect
	// Admin writes test data as an owner; the agent only gets the scanner login.
	Admin *sql.DB
}

func writeSecret(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func open(t *testing.T, driver, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open(driver, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Fatalf("stand database %s is not reachable, run make dev-up: %v", driver, err)
	}
	return db
}

func positional(prefix string) func(int) string {
	return func(count int) string {
		parts := make([]string, count)
		for i := range parts {
			parts[i] = prefix + strconv.Itoa(i+1)
		}
		return strings.Join(parts, ", ")
	}
}

func questionMarks(count int) string {
	return strings.TrimSuffix(strings.Repeat("?, ", count), ", ")
}

func doubleQuote(name string) string { return `"` + name + `"` }

// AllSources opens every engine of the MVP.
func AllSources(t *testing.T) []Source {
	t.Helper()
	return []Source{PostgresSource(t), MySQLSource(t), MariaDBSource(t), MSSQLSource(t)}
}

// PostgresSource returns the stand PostgreSQL.
func PostgresSource(t *testing.T) Source {
	t.Helper()
	env := Env(t)
	dsn := url.URL{
		Scheme: "postgres", User: url.UserPassword("dg_app", env["SOURCE_APP_PASSWORD"]),
		Host: fmt.Sprintf("%s:%d", host, PostgresPort), Path: "/crm", RawQuery: "sslmode=disable",
	}
	return Source{
		Config: config.Source{
			Key: "crm-postgres", Engine: config.EnginePostgreSQL, Host: host, Port: PostgresPort, Database: "crm",
			Username: "dg_scanner", PasswordFile: writeSecret(t, env["SOURCE_SCANNER_PASSWORD"]), TLS: "disable", MaxConnections: 2,
		},
		Admin:   open(t, "pgx", dsn.String()),
		Dialect: seed.Dialect{Name: "postgresql", Text: "text", Bigint: "bigint", Quote: doubleQuote, Placeholders: positional("$")},
	}
}

func mysqlDB(t *testing.T, port int, password string) *sql.DB {
	t.Helper()
	settings := mysql.NewConfig()
	settings.User, settings.Passwd, settings.Net = "dg_app", password, "tcp"
	settings.Addr, settings.DBName = fmt.Sprintf("%s:%d", host, port), "crm"
	settings.TLSConfig = "false"
	return open(t, "mysql", settings.FormatDSN())
}

func backtick(name string) string { return "`" + name + "`" }

// MySQLSource returns the stand MySQL.
func MySQLSource(t *testing.T) Source {
	t.Helper()
	env := Env(t)
	return Source{
		Config: config.Source{
			Key: "crm-mysql", Engine: config.EngineMySQL, Host: host, Port: MySQLPort, Database: "crm",
			Username: "dg_scanner", PasswordFile: writeSecret(t, env["SOURCE_SCANNER_PASSWORD"]), TLS: "disable", MaxConnections: 2,
		},
		Admin:   mysqlDB(t, MySQLPort, env["SOURCE_APP_PASSWORD"]),
		Dialect: seed.Dialect{Name: "mysql", Text: "varchar(255)", Bigint: "bigint", Quote: backtick, Placeholders: questionMarks},
	}
}

// MariaDBSource returns the stand MariaDB.
func MariaDBSource(t *testing.T) Source {
	t.Helper()
	env := Env(t)
	return Source{
		Config: config.Source{
			Key: "crm-mariadb", Engine: config.EngineMariaDB, Host: host, Port: MariaDBPort, Database: "crm",
			Username: "dg_scanner", PasswordFile: writeSecret(t, env["SOURCE_SCANNER_PASSWORD"]), TLS: "disable", MaxConnections: 2,
		},
		Admin:   mysqlDB(t, MariaDBPort, env["SOURCE_APP_PASSWORD"]),
		Dialect: seed.Dialect{Name: "mariadb", Text: "varchar(255)", Bigint: "bigint", Quote: backtick, Placeholders: questionMarks},
	}
}

// MSSQLSource returns the stand SQL Server.
func MSSQLSource(t *testing.T) Source {
	t.Helper()
	env := Env(t)
	query := url.Values{"database": {"crm"}, "encrypt": {"true"}, "TrustServerCertificate": {"true"}}
	dsn := url.URL{
		Scheme: "sqlserver", User: url.UserPassword("dg_app", env["SOURCE_MSSQL_APP_PASSWORD"]),
		Host: fmt.Sprintf("%s:%d", host, MSSQLPort), RawQuery: query.Encode(),
	}
	return Source{
		Config: config.Source{
			Key: "crm-mssql", Engine: config.EngineMSSQL, Host: host, Port: MSSQLPort, Database: "crm",
			Username: "dg_scanner", PasswordFile: writeSecret(t, env["SOURCE_MSSQL_SCANNER_PASSWORD"]), TLS: "require", MaxConnections: 2,
		},
		Admin: open(t, "sqlserver", dsn.String()),
		Dialect: seed.Dialect{
			Name: "mssql", Text: "nvarchar(255)", Bigint: "bigint",
			Quote: func(name string) string { return "[" + name + "]" }, Placeholders: positional("@p"),
		},
	}
}
