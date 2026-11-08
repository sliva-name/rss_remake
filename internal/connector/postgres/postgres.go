// Package postgres adapts PostgreSQL.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the pgx database/sql driver

	"dataguard/internal/connector"
	"dataguard/internal/connector/sqlsource"
	"dataguard/internal/contract/codes"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/safeerr"
)

// Source is a PostgreSQL connection.
type Source struct {
	db       *sql.DB
	database string
}

// Open connects without running a query; the first use reports failures.
func Open(credentials connector.Credentials, maxConnections int) (*Source, error) {
	dsn := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(credentials.Username, credentials.Password),
		Host:   fmt.Sprintf("%s:%d", credentials.Host, credentials.Port),
		Path:   "/" + credentials.Database,
	}
	query := url.Values{"application_name": {"dataguard-scanner"}, "sslmode": {string(credentials.TLS)}}
	dsn.RawQuery = query.Encode()
	db, err := sql.Open("pgx", dsn.String())
	if err != nil {
		return nil, safeerr.New("open postgres source", safeerr.CodeInvalid, err)
	}
	sqlsource.Configure(db, maxConnections)
	return &Source{db: db, database: credentials.Database}, nil
}

// Close releases the pool.
func (s *Source) Close() error { return s.db.Close() }

// Probe reports discovery capabilities and the server version.
func (s *Source) Probe(ctx context.Context) (string, []*agentv1.CapabilityStatus) {
	version, capabilities := sqlsource.Probe(ctx, s.db, `SELECT current_setting('server_version')`, s.auditCapabilities)
	version, _, _ = strings.Cut(version, " ")
	return version, capabilities
}

const auditSettingsQuery = `
SELECT current_setting('shared_preload_libraries'), COALESCE(current_setting('pgaudit.log', true), ''),
       current_setting('log_destination'), current_setting('logging_collector'),
       current_setting('log_disconnections')`

func (s *Source) auditCapabilities(ctx context.Context) []*agentv1.CapabilityStatus {
	var preload, classes, destination, collector, disconnections string
	err := s.db.QueryRowContext(ctx, auditSettingsQuery).Scan(&preload, &classes, &destination, &collector, &disconnections)
	if err != nil {
		return []*agentv1.CapabilityStatus{connector.Status(agentv1.Capability_CAPABILITY_NATIVE_AUDIT, agentv1.Support_SUPPORT_UNKNOWN, codes.ProbeFailed)}
	}
	installed := strings.Contains(preload, "pgaudit")
	readable := installed && collector == "on" && strings.Contains(destination, "jsonlog")
	audited := func(class string) bool {
		return strings.Contains(classes, class) || strings.Contains(classes, "all")
	}
	return []*agentv1.CapabilityStatus{
		connector.Configured(agentv1.Capability_CAPABILITY_NATIVE_AUDIT, readable, codes.PgauditWithJSONLogRequired),
		connector.Configured(agentv1.Capability_CAPABILITY_READ_AUDIT, readable && audited("read"), codes.PgauditReadClassRequired),
		connector.Configured(agentv1.Capability_CAPABILITY_TABLE_LEVEL_AUDIT, readable, codes.DerivedFromQueryText),
		connector.Configured(agentv1.Capability_CAPABILITY_COLUMN_LEVEL_AUDIT, readable, codes.DerivedFromQueryText),
		connector.Configured(agentv1.Capability_CAPABILITY_QUERY_TEXT, readable, ""),
		connector.Configured(agentv1.Capability_CAPABILITY_EXECUTION_STATUS, readable && disconnections == "on", codes.LogDisconnectionsRequired),
		connector.Status(agentv1.Capability_CAPABILITY_RETURNED_ROWS, agentv1.Support_SUPPORT_UNAVAILABLE, codes.NotInNativeAudit),
		connector.Configured(agentv1.Capability_CAPABILITY_APPLICATION_CONTEXT, readable && audited("misc_set"), codes.PgauditMiscSetClassRequired),
	}
}

// LogLocation reports log_timezone, the zone jsonlog prints timestamps in. The
// log carries only its abbreviation, which is ambiguous without the zone.
func (s *Source) LogLocation(ctx context.Context) (*time.Location, error) {
	var name string
	if err := s.db.QueryRowContext(ctx, `SELECT current_setting('log_timezone')`).Scan(&name); err != nil {
		return nil, safeerr.New("read log time zone", safeerr.CodeQuery, err)
	}
	location, err := time.LoadLocation(name)
	if err != nil {
		return nil, safeerr.New("unknown log time zone", safeerr.CodeInvalid, err)
	}
	return location, nil
}

// catalogQuery reads pg_catalog rather than information_schema because the
// latter hides comments, row estimates and materialized views.
const catalogQuery = `
SELECT n.nspname, c.relname, c.relkind::text, c.reltuples::bigint,
       CASE WHEN c.relkind IN ('v', 'm') THEN pg_get_viewdef(c.oid) ELSE '' END,
       a.attname, format_type(a.atttypid, a.atttypmod), a.attnum, NOT a.attnotnull,
       COALESCE(col_description(c.oid, a.attnum), '')
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_attribute a ON a.attrelid = c.oid
WHERE c.relkind IN ('r', 'p', 'v', 'm')
  AND NOT c.relispartition
  AND a.attnum > 0 AND NOT a.attisdropped
  AND n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname !~ '^pg_(toast|temp)'
ORDER BY n.nspname, c.relname, a.attnum`

// Tables lists user tables and views of the connected database.
func (s *Source) Tables(ctx context.Context) ([]connector.Table, error) {
	return sqlsource.Catalog(ctx, s.db, catalogQuery, func(rows *sql.Rows) (connector.Table, connector.Column, error) {
		table := connector.Table{Database: s.database}
		var kind string
		var column connector.Column
		err := rows.Scan(&table.Schema, &table.Name, &kind, &table.EstimatedRows, &table.Definition,
			&column.Name, &column.NativeType, &column.Ordinal, &column.Nullable, &column.Comment)
		table.Kind = tableKind(kind)
		return table, column, err
	})
}

func tableKind(kind string) agentv1.TableKind {
	switch kind {
	case "v":
		return agentv1.TableKind_TABLE_KIND_VIEW
	case "m":
		return agentv1.TableKind_TABLE_KIND_MATERIALIZED_VIEW
	default:
		return agentv1.TableKind_TABLE_KIND_TABLE
	}
}

// Sample reads a bounded sample.
func (s *Source) Sample(ctx context.Context, table connector.Table, columns []connector.Column, limits connector.Limits, visit connector.Visitor) (connector.SampleStats, error) {
	return sqlsource.Sample(ctx, s.db, dialect{}, table, columns, limits, visit)
}

type dialect struct{}

func (dialect) Quote(identifier string) string {
	return sqlsource.QuoteWith(identifier, `"`, `"`)
}

// SampleQuery uses block sampling once a table outgrows the limit.
func (dialect) SampleQuery(target, columns string, estimatedRows int64, maxRows uint64) (string, agentv1.SamplingMethod) {
	percent, sampled := sqlsource.SamplePercent(estimatedRows, maxRows)
	if !sampled {
		return fmt.Sprintf(`SELECT %s FROM %s LIMIT %d`, columns, target, maxRows), agentv1.SamplingMethod_SAMPLING_METHOD_BOUNDED_PREFIX
	}
	return fmt.Sprintf(`SELECT %s FROM %s TABLESAMPLE SYSTEM (%.6f) LIMIT %d`, columns, target, percent, maxRows),
		agentv1.SamplingMethod_SAMPLING_METHOD_ENGINE_SAMPLE
}

func (dialect) TxOptions() *sql.TxOptions {
	return &sql.TxOptions{ReadOnly: true}
}

func (dialect) Prepare(ctx context.Context, tx *sql.Tx) error {
	statement := fmt.Sprintf(`SET LOCAL statement_timeout = %d; SET LOCAL lock_timeout = %d`,
		sqlsource.StatementTimeout.Milliseconds(), sqlsource.LockTimeout.Milliseconds())
	_, err := tx.ExecContext(ctx, statement)
	return err
}
