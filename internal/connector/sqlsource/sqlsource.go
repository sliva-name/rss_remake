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
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/safeerr"
)

const (
	limiterBatch = 256
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
	// SampleQuery returns the statement and the method it implements. All names
	// come from the catalog and are quoted by Quote.
	SampleQuery(table connector.Table, quotedColumns []string, maxRows uint64) (string, agentv1.SamplingMethod)
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
	query, method := dialect.SampleQuery(table, quoted, limits.MaxRows)
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
	if limits.Limiter == nil || rowsSoFar%limiterBatch != 0 {
		return nil
	}
	if err := limits.Limiter.WaitN(ctx, min(limiterBatch, limits.Limiter.Burst())); err != nil {
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
