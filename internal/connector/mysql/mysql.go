// Package mysql adapts MySQL and MariaDB. They share the wire protocol and the
// catalog; the differences that matter to a scanner are handled by Flavor.
package mysql

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/go-sql-driver/mysql"

	"dataguard/internal/connector"
	"dataguard/internal/connector/sqlsource"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/safeerr"
)

// Flavor selects the engine variant.
type Flavor int

const (
	FlavorMySQL Flavor = iota
	FlavorMariaDB
)

// Source is a MySQL-family connection.
type Source struct {
	db       *sql.DB
	database string
	flavor   Flavor
}

// Open connects without running a query.
func Open(credentials connector.Credentials, flavor Flavor, maxConnections int) (*Source, error) {
	config := mysql.NewConfig()
	config.User = credentials.Username
	config.Passwd = credentials.Password
	config.Net = "tcp"
	config.Addr = net.JoinHostPort(credentials.Host, strconv.Itoa(credentials.Port))
	config.DBName = credentials.Database
	config.ParseTime = false
	switch credentials.TLS {
	case connector.TLSDisable:
		config.TLSConfig = "false"
	case connector.TLSRequire:
		config.TLSConfig = "skip-verify"
	default:
		config.TLSConfig = "true"
	}
	connection, err := mysql.NewConnector(config)
	if err != nil {
		return nil, safeerr.New("open mysql source", safeerr.CodeInvalid, err)
	}
	db := sql.OpenDB(connection)
	sqlsource.Configure(db, maxConnections)
	return &Source{db: db, database: credentials.Database, flavor: flavor}, nil
}

// Close releases the pool.
func (s *Source) Close() error { return s.db.Close() }

// Probe reports discovery capabilities and the server version.
func (s *Source) Probe(ctx context.Context) (string, []*agentv1.CapabilityStatus) {
	var version string
	if err := s.db.QueryRowContext(ctx, `SELECT VERSION()`).Scan(&version); err != nil {
		return "", []*agentv1.CapabilityStatus{
			connector.Status(agentv1.Capability_CAPABILITY_SCHEMA_DISCOVERY, agentv1.Support_SUPPORT_UNKNOWN, "PROBE_FAILED"),
			connector.Status(agentv1.Capability_CAPABILITY_COLUMN_PROFILING, agentv1.Support_SUPPORT_UNKNOWN, "PROBE_FAILED"),
		}
	}
	return version, append([]*agentv1.CapabilityStatus{
		connector.Status(agentv1.Capability_CAPABILITY_SCHEMA_DISCOVERY, agentv1.Support_SUPPORT_AVAILABLE, ""),
		connector.Status(agentv1.Capability_CAPABILITY_COLUMN_PROFILING, agentv1.Support_SUPPORT_AVAILABLE, ""),
	}, s.auditCapabilities(ctx)...)
}

func (s *Source) auditCapabilities(ctx context.Context) []*agentv1.CapabilityStatus {
	query, reason := `SELECT @@general_log = 1 AND @@log_output LIKE '%FILE%'`, "GENERAL_LOG_REQUIRED"
	if s.flavor == FlavorMariaDB {
		query, reason = `SELECT @@server_audit_logging = 1 AND @@server_audit_output_type = 'FILE'`, "SERVER_AUDIT_REQUIRED"
	}
	var enabled bool
	if err := s.db.QueryRowContext(ctx, query).Scan(&enabled); err != nil {
		return []*agentv1.CapabilityStatus{connector.Status(agentv1.Capability_CAPABILITY_NATIVE_AUDIT, agentv1.Support_SUPPORT_NOT_CONFIGURED, reason)}
	}
	statuses := []*agentv1.CapabilityStatus{
		connector.Configured(agentv1.Capability_CAPABILITY_NATIVE_AUDIT, enabled, reason),
		connector.Configured(agentv1.Capability_CAPABILITY_READ_AUDIT, enabled, reason),
		connector.Configured(agentv1.Capability_CAPABILITY_TABLE_LEVEL_AUDIT, enabled, "DERIVED_FROM_QUERY_TEXT"),
		connector.Configured(agentv1.Capability_CAPABILITY_COLUMN_LEVEL_AUDIT, enabled, "DERIVED_FROM_QUERY_TEXT"),
		connector.Configured(agentv1.Capability_CAPABILITY_QUERY_TEXT, enabled, reason),
		connector.Status(agentv1.Capability_CAPABILITY_RETURNED_ROWS, agentv1.Support_SUPPORT_UNAVAILABLE, "NOT_IN_NATIVE_AUDIT"),
		connector.Status(agentv1.Capability_CAPABILITY_APPLICATION_CONTEXT, agentv1.Support_SUPPORT_UNAVAILABLE, "NOT_IMPLEMENTED_FOR_ENGINE"),
	}
	if s.flavor == FlavorMariaDB {
		return append(statuses, connector.Configured(agentv1.Capability_CAPABILITY_EXECUTION_STATUS, enabled, reason))
	}
	return append(statuses, connector.Status(agentv1.Capability_CAPABILITY_EXECUTION_STATUS, agentv1.Support_SUPPORT_UNAVAILABLE, "GENERAL_LOG_HAS_NO_OUTCOME"))
}

const catalogQuery = `
SELECT t.TABLE_NAME, t.TABLE_TYPE, COALESCE(t.TABLE_ROWS, -1), COALESCE(v.VIEW_DEFINITION, ''),
       c.COLUMN_NAME, c.COLUMN_TYPE, c.ORDINAL_POSITION, c.IS_NULLABLE = 'YES', c.COLUMN_COMMENT
FROM information_schema.TABLES t
JOIN information_schema.COLUMNS c ON c.TABLE_SCHEMA = t.TABLE_SCHEMA AND c.TABLE_NAME = t.TABLE_NAME
LEFT JOIN information_schema.VIEWS v ON v.TABLE_SCHEMA = t.TABLE_SCHEMA AND v.TABLE_NAME = t.TABLE_NAME
WHERE t.TABLE_SCHEMA = DATABASE()
ORDER BY t.TABLE_NAME, c.ORDINAL_POSITION`

// Tables lists tables and views of the connected database. MySQL has no schema
// level below the database, so Schema repeats the database name, which is also
// how the engine itself treats the two.
func (s *Source) Tables(ctx context.Context) ([]connector.Table, error) {
	rows, err := s.db.QueryContext(ctx, catalogQuery)
	if err != nil {
		return nil, safeerr.New("read catalog", safeerr.CodeQuery, err)
	}
	defer func() { _ = rows.Close() }()

	var tables []connector.Table
	for rows.Next() {
		var name, kind, definition string
		var estimate int64
		var column connector.Column
		if err := rows.Scan(&name, &kind, &estimate, &definition, &column.Name, &column.NativeType,
			&column.Ordinal, &column.Nullable, &column.Comment); err != nil {
			return nil, safeerr.New("decode catalog row", safeerr.CodeQuery, err)
		}
		last := len(tables) - 1
		if last < 0 || tables[last].Name != name {
			tables = append(tables, connector.Table{
				Database: s.database, Schema: s.database, Name: name, Kind: tableKind(kind),
				EstimatedRows: estimate, Definition: definition,
			})
			last++
		}
		tables[last].Columns = append(tables[last].Columns, column)
	}
	if err := rows.Err(); err != nil {
		return nil, safeerr.New("read catalog", safeerr.CodeQuery, err)
	}
	return tables, nil
}

func tableKind(kind string) agentv1.TableKind {
	if strings.Contains(kind, "VIEW") {
		return agentv1.TableKind_TABLE_KIND_VIEW
	}
	return agentv1.TableKind_TABLE_KIND_TABLE
}

// Sample reads a bounded sample.
func (s *Source) Sample(ctx context.Context, table connector.Table, columns []connector.Column, limits connector.Limits, visit connector.Visitor) (connector.SampleStats, error) {
	return sqlsource.Sample(ctx, s.db, dialect{flavor: s.flavor}, table, columns, limits, visit)
}

type dialect struct {
	flavor Flavor
}

func (dialect) Quote(identifier string) string {
	return sqlsource.QuoteWith(identifier, "`", "`")
}

// SampleQuery has no engine sampling to use, so it reads a prefix. The prefix
// follows storage order and may be biased towards old rows; the result reports
// SAMPLING_METHOD_BOUNDED_PREFIX so this stays visible.
func (d dialect) SampleQuery(table connector.Table, quotedColumns []string, maxRows uint64) (string, agentv1.SamplingMethod) {
	target := d.Quote(table.Schema) + "." + d.Quote(table.Name)
	return fmt.Sprintf(`SELECT %s FROM %s LIMIT %d`, strings.Join(quotedColumns, ", "), target, maxRows),
		agentv1.SamplingMethod_SAMPLING_METHOD_BOUNDED_PREFIX
}

func (dialect) TxOptions() *sql.TxOptions {
	return &sql.TxOptions{ReadOnly: true}
}

// Prepare differs by flavor: MySQL counts milliseconds in max_execution_time,
// MariaDB counts seconds in max_statement_time.
func (d dialect) Prepare(ctx context.Context, tx *sql.Tx) error {
	statement := fmt.Sprintf(`SET SESSION max_execution_time = %d`, sqlsource.StatementTimeout.Milliseconds())
	if d.flavor == FlavorMariaDB {
		statement = fmt.Sprintf(`SET SESSION max_statement_time = %d`, int(sqlsource.StatementTimeout.Seconds()))
	}
	if _, err := tx.ExecContext(ctx, statement); err != nil {
		return err
	}
	lockTimeout := fmt.Sprintf(`SET SESSION innodb_lock_wait_timeout = %d`, int(sqlsource.LockTimeout.Seconds()))
	_, err := tx.ExecContext(ctx, lockTimeout)
	return err
}
