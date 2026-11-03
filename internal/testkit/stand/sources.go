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

// spec is a stand database before its owner connection is opened.
type spec struct {
	config  sources.Definition
	dialect seed.Dialect
	driver  string
	dsn     string
}

func mysqlDSN(port int, password string) string {
	settings := mysql.NewConfig()
	settings.User, settings.Passwd, settings.Net = "dg_app", password, "tcp"
	settings.Addr, settings.DBName = fmt.Sprintf("%s:%d", host, port), "crm"
	settings.TLSConfig = "false"
	return settings.FormatDSN()
}

func backtick(name string) string { return "`" + name + "`" }

// specs lists the engines of the MVP in a fixed order: PostgreSQL, MySQL,
// MariaDB, SQL Server.
func specs(env map[string]string) []spec {
	postgresDSN := url.URL{
		Scheme: "postgres", User: url.UserPassword("dg_app", env["SOURCE_APP_PASSWORD"]),
		Host: fmt.Sprintf("%s:%d", host, PostgresPort), Path: "/crm", RawQuery: "sslmode=disable",
	}
	mssqlQuery := url.Values{"database": {"crm"}, "encrypt": {"true"}, "TrustServerCertificate": {"true"}}
	mssqlDSN := url.URL{
		Scheme: "sqlserver", User: url.UserPassword("dg_app", env["SOURCE_MSSQL_APP_PASSWORD"]),
		Host: fmt.Sprintf("%s:%d", host, MSSQLPort), RawQuery: mssqlQuery.Encode(),
	}
	definition := func(name, engine string, port int, password, tls string) sources.Definition {
		return sources.Definition{
			Name: name, Engine: engine, Host: host, Port: port, Database: "crm",
			Username: "dg_scanner", Password: password, TLS: tls, MaxConnections: 2,
		}
	}
	return []spec{{
		config:  definition("crm-postgres", sources.EnginePostgreSQL, PostgresPort, env["SOURCE_SCANNER_PASSWORD"], "disable"),
		dialect: seed.Dialect{Name: "postgresql", Text: "text", Bigint: "bigint", Quote: doubleQuote, Placeholders: positional("$")},
		driver:  "pgx", dsn: postgresDSN.String(),
	}, {
		config:  definition("crm-mysql", sources.EngineMySQL, MySQLPort, env["SOURCE_SCANNER_PASSWORD"], "disable"),
		dialect: seed.Dialect{Name: "mysql", Text: "varchar(255)", Bigint: "bigint", Quote: backtick, Placeholders: questionMarks},
		driver:  "mysql", dsn: mysqlDSN(MySQLPort, env["SOURCE_APP_PASSWORD"]),
	}, {
		config:  definition("crm-mariadb", sources.EngineMariaDB, MariaDBPort, env["SOURCE_SCANNER_PASSWORD"], "disable"),
		dialect: seed.Dialect{Name: "mariadb", Text: "varchar(255)", Bigint: "bigint", Quote: backtick, Placeholders: questionMarks},
		driver:  "mysql", dsn: mysqlDSN(MariaDBPort, env["SOURCE_APP_PASSWORD"]),
	}, {
		config: definition("crm-mssql", sources.EngineMSSQL, MSSQLPort, env["SOURCE_MSSQL_SCANNER_PASSWORD"], "require"),
		dialect: seed.Dialect{
			Name: "mssql", Text: "nvarchar(255)", Bigint: "bigint",
			Quote: func(name string) string { return "[" + name + "]" }, Placeholders: positional("@p"),
		},
		driver: "sqlserver", dsn: mssqlDSN.String(),
	}}
}

func connect(driver, dsn string) (*sql.DB, error) {
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("stand database %s is not reachable, run make dev-up: %w", driver, err)
	}
	return db, nil
}

// OpenSources is AllSources outside a test. The caller closes Admin.
func OpenSources(env map[string]string) ([]Source, error) {
	var opened []Source
	for _, item := range specs(env) {
		db, err := connect(item.driver, item.dsn)
		if err != nil {
			for _, source := range opened {
				_ = source.Admin.Close()
			}
			return nil, err
		}
		opened = append(opened, Source{Config: item.config, Dialect: item.dialect, Admin: db})
	}
	return opened, nil
}

func sourceAt(t *testing.T, index int) Source {
	t.Helper()
	item := specs(Env(t))[index]
	db, err := connect(item.driver, item.dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return Source{Config: item.config, Dialect: item.dialect, Admin: db}
}

// AllSources opens every engine of the MVP.
func AllSources(t *testing.T) []Source {
	t.Helper()
	return []Source{PostgresSource(t), MySQLSource(t), MariaDBSource(t), MSSQLSource(t)}
}

// PostgresSource returns the stand PostgreSQL.
func PostgresSource(t *testing.T) Source { t.Helper(); return sourceAt(t, 0) }

// MySQLSource returns the stand MySQL.
func MySQLSource(t *testing.T) Source { t.Helper(); return sourceAt(t, 1) }

// MariaDBSource returns the stand MariaDB.
func MariaDBSource(t *testing.T) Source { t.Helper(); return sourceAt(t, 2) }

// MSSQLSource returns the stand SQL Server.
func MSSQLSource(t *testing.T) Source { t.Helper(); return sourceAt(t, 3) }

// ContainerSources are the stand databases as the agent container reaches
// them: by service name, on internal ports, with their audit directories.
func ContainerSources(env map[string]string) []sources.Definition {
	definition := func(name, engine, host string, port int, passwordKey, tls, auditDirectory string) sources.Definition {
		return sources.Definition{
			Name: name, Engine: engine, Host: host, Port: port, Database: "crm", Username: "dg_scanner",
			Password: env[passwordKey], TLS: tls, MaxConnections: 2, AuditDirectory: auditDirectory,
		}
	}
	return []sources.Definition{
		definition("crm-postgres", sources.EnginePostgreSQL, "source-postgres", 5432, "SOURCE_SCANNER_PASSWORD", "disable", "/var/log/dg-audit/postgres"),
		definition("crm-mysql", sources.EngineMySQL, "source-mysql", 3306, "SOURCE_SCANNER_PASSWORD", "disable", "/var/log/dg-audit/mysql"),
		definition("crm-mariadb", sources.EngineMariaDB, "source-mariadb", 3306, "SOURCE_SCANNER_PASSWORD", "disable", "/var/log/dg-audit/mariadb"),
		// SQL Server reads its audit through SQL, from a path on its own server.
		definition("crm-mssql", sources.EngineMSSQL, "source-mssql", 1433, "SOURCE_MSSQL_SCANNER_PASSWORD", "require", "/var/opt/mssql/dg-audit"),
	}
}
