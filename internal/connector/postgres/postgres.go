// Package postgres adapts PostgreSQL.
package postgres

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the pgx database/sql driver

	"dataguard/internal/connector"
	"dataguard/internal/connector/sqlsource"
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
	var version string
	if err := s.db.QueryRowContext(ctx, `SELECT current_setting('server_version')`).Scan(&version); err != nil {
		return "", []*agentv1.CapabilityStatus{
			connector.Status(agentv1.Capability_CAPABILITY_SCHEMA_DISCOVERY, agentv1.Support_SUPPORT_UNKNOWN, "PROBE_FAILED"),
			connector.Status(agentv1.Capability_CAPABILITY_COLUMN_PROFILING, agentv1.Support_SUPPORT_UNKNOWN, "PROBE_FAILED"),
		}
	}
	version, _, _ = strings.Cut(version, " ")
	return version, []*agentv1.CapabilityStatus{
		connector.Status(agentv1.Capability_CAPABILITY_SCHEMA_DISCOVERY, agentv1.Support_SUPPORT_AVAILABLE, ""),
		connector.Status(agentv1.Capability_CAPABILITY_COLUMN_PROFILING, agentv1.Support_SUPPORT_AVAILABLE, ""),
	}
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
	rows, err := s.db.QueryContext(ctx, catalogQuery)
	if err != nil {
		return nil, safeerr.New("read catalog", safeerr.CodeQuery, err)
	}
	defer func() { _ = rows.Close() }()

	var tables []connector.Table
	for rows.Next() {
		var schema, name, kind, definition string
		var estimate int64
		var column connector.Column
		if err := rows.Scan(&schema, &name, &kind, &estimate, &definition, &column.Name, &column.NativeType,
			&column.Ordinal, &column.Nullable, &column.Comment); err != nil {
			return nil, safeerr.New("decode catalog row", safeerr.CodeQuery, err)
		}
		last := len(tables) - 1
		if last < 0 || tables[last].Schema != schema || tables[last].Name != name {
			tables = append(tables, connector.Table{
				Database: s.database, Schema: schema, Name: name, Kind: tableKind(kind),
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

// SampleQuery uses block sampling once a table outgrows the limit. Because
// SYSTEM sampling returns whole pages, the percentage is padded so the LIMIT,
// not the sample, normally ends the read.
func (d dialect) SampleQuery(table connector.Table, quotedColumns []string, maxRows uint64) (string, agentv1.SamplingMethod) {
	const samplePadding = 3.0
	list := strings.Join(quotedColumns, ", ")
	target := d.Quote(table.Schema) + "." + d.Quote(table.Name)
	if table.EstimatedRows <= int64(maxRows) {
		return fmt.Sprintf(`SELECT %s FROM %s LIMIT %d`, list, target, maxRows), agentv1.SamplingMethod_SAMPLING_METHOD_BOUNDED_PREFIX
	}
	percent := min(100, samplePadding*100*float64(maxRows)/float64(table.EstimatedRows))
	return fmt.Sprintf(`SELECT %s FROM %s TABLESAMPLE SYSTEM (%.6f) LIMIT %d`, list, target, percent, maxRows),
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
