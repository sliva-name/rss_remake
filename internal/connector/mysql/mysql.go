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
	"time"

	"github.com/go-sql-driver/mysql"

	"dataguard/internal/connector"
	"dataguard/internal/connector/sqlsource"
	"dataguard/internal/contract/codes"
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
	return sqlsource.Probe(ctx, s.db, `SELECT VERSION()`, s.auditCapabilities)
}

func (s *Source) auditCapabilities(ctx context.Context) []*agentv1.CapabilityStatus {
	query, reason := `SELECT @@general_log = 1 AND @@log_output LIKE '%FILE%'`, codes.GeneralLogRequired
	if s.flavor == FlavorMariaDB {
		query, reason = `SELECT @@server_audit_logging = 1 AND @@server_audit_output_type = 'FILE'`, codes.ServerAuditRequired
	}
	var enabled bool
	if err := s.db.QueryRowContext(ctx, query).Scan(&enabled); err != nil {
		return []*agentv1.CapabilityStatus{connector.Status(agentv1.Capability_CAPABILITY_NATIVE_AUDIT, agentv1.Support_SUPPORT_NOT_CONFIGURED, reason)}
	}
	statuses := []*agentv1.CapabilityStatus{
		connector.Configured(agentv1.Capability_CAPABILITY_NATIVE_AUDIT, enabled, reason),
		connector.Configured(agentv1.Capability_CAPABILITY_READ_AUDIT, enabled, reason),
		connector.Configured(agentv1.Capability_CAPABILITY_TABLE_LEVEL_AUDIT, enabled, codes.DerivedFromQueryText),
		connector.Configured(agentv1.Capability_CAPABILITY_COLUMN_LEVEL_AUDIT, enabled, codes.DerivedFromQueryText),
		connector.Configured(agentv1.Capability_CAPABILITY_QUERY_TEXT, enabled, reason),
		connector.Status(agentv1.Capability_CAPABILITY_RETURNED_ROWS, agentv1.Support_SUPPORT_UNAVAILABLE, codes.NotInNativeAudit),
		connector.Status(agentv1.Capability_CAPABILITY_APPLICATION_CONTEXT, agentv1.Support_SUPPORT_UNAVAILABLE, codes.NotImplementedForEngine),
	}
	if s.flavor == FlavorMariaDB {
		return append(statuses, connector.Configured(agentv1.Capability_CAPABILITY_EXECUTION_STATUS, enabled, reason))
	}
	return append(statuses, connector.Status(agentv1.Capability_CAPABILITY_EXECUTION_STATUS, agentv1.Support_SUPPORT_UNAVAILABLE, codes.GeneralLogHasNoOutcome))
}

// LogLocation reports the zone of server_audit timestamps, which are the
// server process's local time without an offset. The offset is fixed at the
// moment of the call; the collector asks again every few minutes, so a daylight
// saving change misplaces records by an hour for at most that long.
func (s *Source) LogLocation(ctx context.Context) (*time.Location, error) {
	const query = `SELECT TIMESTAMPDIFF(SECOND, UTC_TIMESTAMP(), CONVERT_TZ(UTC_TIMESTAMP(), '+00:00', 'SYSTEM'))`
	var offset int
	if err := s.db.QueryRowContext(ctx, query).Scan(&offset); err != nil {
		return nil, safeerr.New("read log time zone", safeerr.CodeQuery, err)
	}
	return time.FixedZone("", offset), nil
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
	return sqlsource.Catalog(ctx, s.db, catalogQuery, func(rows *sql.Rows) (connector.Table, connector.Column, error) {
		table := connector.Table{Database: s.database, Schema: s.database}
		var kind string
		var column connector.Column
		err := rows.Scan(&table.Name, &kind, &table.EstimatedRows, &table.Definition,
			&column.Name, &column.NativeType, &column.Ordinal, &column.Nullable, &column.Comment)
		table.Kind = tableKind(kind)
		return table, column, err
	})
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
func (dialect) SampleQuery(target, columns string, _ int64, maxRows uint64) (string, agentv1.SamplingMethod) {
	return fmt.Sprintf(`SELECT %s FROM %s LIMIT %d`, columns, target, maxRows),
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
