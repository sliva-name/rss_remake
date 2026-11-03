package stand

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"  // registers the driver
	_ "github.com/microsoft/go-mssqldb" // registers the driver

	"dataguard/internal/agent/sources"
	"dataguard/internal/testkit/seed"
)

// AuditDirectory returns where the stand exposes an engine's audit logs. SQL Server
// logs are read through SQL, so its path is the one inside the server.
func AuditDirectory(engine string) string {
	if engine == "mssql" {
		return "/var/opt/mssql/dg-audit"
	}
	if engine == "postgresql" {
		engine = "postgres"
	}
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "deployments", "dev", ".state", "audit", engine)
}

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
	// Config has an empty ID: a test assigns one, or the center does.
	Config  sources.Definition
	Dialect seed.Dialect
	// Admin writes test data as an owner; the agent only gets the scanner login.
	Admin *sql.DB
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
		Config: sources.Definition{
			Name: "crm-postgres", Engine: sources.EnginePostgreSQL, Host: host, Port: PostgresPort, Database: "crm",
			Username: "dg_scanner", Password: env["SOURCE_SCANNER_PASSWORD"], TLS: "disable", MaxConnections: 2,
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
		Config: sources.Definition{
			Name: "crm-mysql", Engine: sources.EngineMySQL, Host: host, Port: MySQLPort, Database: "crm",
			Username: "dg_scanner", Password: env["SOURCE_SCANNER_PASSWORD"], TLS: "disable", MaxConnections: 2,
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
		Config: sources.Definition{
			Name: "crm-mariadb", Engine: sources.EngineMariaDB, Host: host, Port: MariaDBPort, Database: "crm",
			Username: "dg_scanner", Password: env["SOURCE_SCANNER_PASSWORD"], TLS: "disable", MaxConnections: 2,
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
		Config: sources.Definition{
			Name: "crm-mssql", Engine: sources.EngineMSSQL, Host: host, Port: MSSQLPort, Database: "crm",
			Username: "dg_scanner", Password: env["SOURCE_MSSQL_SCANNER_PASSWORD"], TLS: "require", MaxConnections: 2,
		},
		Admin: open(t, "sqlserver", dsn.String()),
		Dialect: seed.Dialect{
			Name: "mssql", Text: "nvarchar(255)", Bigint: "bigint",
			Quote: func(name string) string { return "[" + name + "]" }, Placeholders: positional("@p"),
		},
	}
}
