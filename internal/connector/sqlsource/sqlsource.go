// Package sqlsource holds the read loop shared by database/sql adapters. Budget
// enforcement and buffer wiping live here so that every engine gets them; only
// the SQL differs.
package sqlsource

import (
	"context"
	"database/sql"
	"strings"
	"time"

	"dataguard/internal/connector"
	"dataguard/internal/contract/codes"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/safeerr"
)

const (
	// LimiterBatch is how many rows are paid for at once.
	LimiterBatch = 256
	// Pool lifetimes keep a scanner from pinning sessions on a production server.
	connectionMaxLifetime = 5 * time.Minute
	connectionMaxIdle     = time.Minute
	// StatementTimeout bounds one sampling query.
	StatementTimeout = 2 * time.Minute
	// LockTimeout makes a scan give up instead of queueing behind a writer.
	LockTimeout = 2 * time.Second
)

// Dialect supplies engine-specific SQL.
type Dialect interface {
	Quote(identifier string) string
	// SampleQuery returns the statement reading at most maxRows of columns from
	// target, and the method it implements. Both are names from the catalog,
	// already quoted by Quote.
	SampleQuery(target, columns string, estimatedRows int64, maxRows uint64) (string, agentv1.SamplingMethod)
	// TxOptions returns the strongest read protection the driver supports.
	TxOptions() *sql.TxOptions
	// Prepare applies statement and lock timeouts inside the transaction.
	Prepare(ctx context.Context, tx *sql.Tx) error
}

// Configure bounds a pool so a scan cannot exhaust the server's connections.
func Configure(db *sql.DB, maxConnections int) {
	db.SetMaxOpenConns(maxConnections)
	db.SetMaxIdleConns(maxConnections)
	db.SetConnMaxLifetime(connectionMaxLifetime)
	db.SetConnMaxIdleTime(connectionMaxIdle)
}

// Probe reads the server version with versionQuery. A server that answers can
// be discovered and profiled, and audit adds what its log can show; one that
// does not leaves discovery unknown.
func Probe(ctx context.Context, db *sql.DB, versionQuery string, audit func(context.Context) []*agentv1.CapabilityStatus) (string, []*agentv1.CapabilityStatus) {
	var version string
	if err := db.QueryRowContext(ctx, versionQuery).Scan(&version); err != nil {
		return "", []*agentv1.CapabilityStatus{
			connector.Status(agentv1.Capability_CAPABILITY_SCHEMA_DISCOVERY, agentv1.Support_SUPPORT_UNKNOWN, codes.ProbeFailed),
			connector.Status(agentv1.Capability_CAPABILITY_COLUMN_PROFILING, agentv1.Support_SUPPORT_UNKNOWN, codes.ProbeFailed),
		}
	}
	return version, append([]*agentv1.CapabilityStatus{
		connector.Status(agentv1.Capability_CAPABILITY_SCHEMA_DISCOVERY, agentv1.Support_SUPPORT_AVAILABLE, ""),
		connector.Status(agentv1.Capability_CAPABILITY_COLUMN_PROFILING, agentv1.Support_SUPPORT_AVAILABLE, ""),
	}, audit(ctx)...)
}

// CatalogRow decodes one row of a catalog query: a column and the table it
// belongs to, whose Columns stay empty.
type CatalogRow func(rows *sql.Rows) (connector.Table, connector.Column, error)

// Catalog runs a catalog query and folds its rows into tables. The query must
// order rows by schema, table and column position, so a table's columns come
// together.
func Catalog(ctx context.Context, db *sql.DB, query string, decode CatalogRow) ([]connector.Table, error) {
	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, safeerr.New("read catalog", safeerr.CodeQuery, err)
	}
	defer func() { _ = rows.Close() }()

	var tables []connector.Table
	for rows.Next() {
		table, column, err := decode(rows)
		if err != nil {
			return nil, safeerr.New("decode catalog row", safeerr.CodeQuery, err)
		}
		last := len(tables) - 1
		if last < 0 || tables[last].Schema != table.Schema || tables[last].Name != table.Name {
			tables = append(tables, table)
			last++
		}
		tables[last].Columns = append(tables[last].Columns, column)
	}
	if err := rows.Err(); err != nil {
		return nil, safeerr.New("read catalog", safeerr.CodeQuery, err)
	}
	return tables, nil
}

// SamplePercent is the share of a table that engine sampling should read, or
// false when the whole table fits in maxRows and a prefix reads it all.
// Engines sample whole pages, so the share is padded: the LIMIT, not the
// sample, normally ends the read.
func SamplePercent(estimatedRows int64, maxRows uint64) (float64, bool) {
	const padding = 3.0
	if estimatedRows <= int64(maxRows) {
		return 0, false
	}
	return min(100, padding*100*float64(maxRows)/float64(estimatedRows)), true
}

// Sample streams a bounded read through visit. Driver errors are converted to
// codes here, because their text can quote row values.
func Sample(ctx context.Context, db *sql.DB, dialect Dialect, table connector.Table, columns []connector.Column, limits connector.Limits, visit connector.Visitor) (connector.SampleStats, error) {
	tx, err := db.BeginTx(ctx, dialect.TxOptions())
	if err != nil {
		return connector.SampleStats{}, safeerr.New("begin sample", safeerr.CodeUnavailable, err)
	}
	// Reads only: rolling back is the normal way to end this transaction.
	defer func() { _ = tx.Rollback() }()

	if err := dialect.Prepare(ctx, tx); err != nil {
		return connector.SampleStats{}, safeerr.New("prepare sample", safeerr.CodeQuery, err)
	}
	quoted := make([]string, len(columns))
	for i, column := range columns {
		quoted[i] = dialect.Quote(column.Name)
	}
	target := dialect.Quote(table.Schema) + "." + dialect.Quote(table.Name)
	query, method := dialect.SampleQuery(target, strings.Join(quoted, ", "), table.EstimatedRows, limits.MaxRows)
	rows, err := tx.QueryContext(ctx, query)
	if err != nil {
		return connector.SampleStats{}, safeerr.New("run sample", safeerr.CodeQuery, err)
	}
	defer func() { _ = rows.Close() }()

	stats := connector.SampleStats{Method: method}
	if err := drain(ctx, rows, len(columns), limits, visit, &stats); err != nil {
		return stats, err
	}
	if err := rows.Err(); err != nil {
		return stats, safeerr.New("read sample", safeerr.CodeQuery, err)
	}
	if method == agentv1.SamplingMethod_SAMPLING_METHOD_BOUNDED_PREFIX && stats.Rows < limits.MaxRows && !stats.Truncated {
		stats.Method = agentv1.SamplingMethod_SAMPLING_METHOD_FULL_SCAN
	}
	return stats, nil
}

func drain(ctx context.Context, rows *sql.Rows, columnCount int, limits connector.Limits, visit connector.Visitor, stats *connector.SampleStats) error {
	values := make([]sql.RawBytes, columnCount)
	destinations := make([]any, columnCount)
	for i := range values {
		destinations[i] = &values[i]
	}
	var bytesRead uint64
	for rows.Next() {
		if err := throttle(ctx, limits, stats.Rows); err != nil {
			return err
		}
		if err := rows.Scan(destinations...); err != nil {
			return safeerr.New("decode sample row", safeerr.CodeQuery, err)
		}
		bytesRead += deliver(values, visit)
		stats.Rows++
		if stats.Rows >= limits.MaxRows {
			return nil
		}
		if limits.MaxBytes > 0 && bytesRead >= limits.MaxBytes {
			stats.Truncated = true
			return nil
		}
	}
	return nil
}

func throttle(ctx context.Context, limits connector.Limits, rowsSoFar uint64) error {
	if limits.Limiter == nil || rowsSoFar%LimiterBatch != 0 {
		return nil
	}
	if err := limits.Limiter.WaitN(ctx, min(LimiterBatch, limits.Limiter.Burst())); err != nil {
		return safeerr.New("throttle sample", safeerr.CodeCanceled, err)
	}
	return nil
}

func deliver(values []sql.RawBytes, visit connector.Visitor) uint64 {
	var size uint64
	for i, value := range values {
		if value == nil {
			continue
		}
		visit(i, value)
		size += uint64(len(value))
		clear(value)
	}
	return size
}

// QuoteWith doubles the closing quote, which is how all supported engines escape
// an identifier.
func QuoteWith(identifier, opening, closing string) string {
	return opening + strings.ReplaceAll(identifier, closing, closing+closing) + closing
}

// ValueBearing reports whether a column can hold text worth inspecting. Dates,
// booleans and binary blobs cannot match any detector, and skipping them keeps
// the query narrow.
func ValueBearing(nativeType string) bool {
	lower := strings.ToLower(nativeType)
	for _, marker := range []string{"char", "text", "string", "bigint", "numeric", "decimal", "citext"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
