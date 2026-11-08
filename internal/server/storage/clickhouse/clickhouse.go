// Package clickhouse stores audit events. Reads go through two independent locks:
// the query filters by tenant, and the row policy on the server filters by the
// session setting.
package clickhouse

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/ext"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"
	"github.com/pressly/goose/v3"
	"github.com/pressly/goose/v3/database"

	"dataguard/internal/core/audit"
	"dataguard/internal/platform/safeerr"
)

const (
	dialTimeout        = 5 * time.Second
	readTimeout        = 30 * time.Second
	statusFail         = "EXECUTION_STATUS_FAILURE"
	typeGap            = "EVENT_TYPE_AUDIT_GAP"
	typeAuth           = "EVENT_TYPE_AUTHENTICATION"
	confidenceVerified = "IDENTITY_CONFIDENCE_VERIFIED"
	confidenceUnknown  = "IDENTITY_CONFIDENCE_UNKNOWN"
	resolved           = "OBJECT_RESOLUTION_RESOLVED"
	tenantSetting      = "SQL_tenant_id"
)

// Settings locate a database.
type Settings struct {
	Address  string
	Database string
	Username string
	Password string
}

func options(settings Settings) *clickhouse.Options {
	return &clickhouse.Options{
		Addr:        []string{settings.Address},
		Auth:        clickhouse.Auth{Database: settings.Database, Username: settings.Username, Password: settings.Password},
		DialTimeout: dialTimeout, ReadTimeout: readTimeout,
	}
}

func open(settings Settings) (driver.Conn, error) {
	return clickhouse.Open(options(settings))
}

// Store reads and writes audit events.
type Store struct {
	conn driver.Conn
}

// Open connects.
func Open(ctx context.Context, settings Settings) (*Store, error) {
	conn, err := open(settings)
	if err != nil {
		return nil, safeerr.New("open clickhouse", safeerr.CodeInvalid, err)
	}
	if err := conn.Ping(ctx); err != nil {
		return nil, errors.Join(safeerr.New("ping clickhouse", safeerr.CodeUnavailable, err), conn.Close())
	}
	return &Store{conn: conn}, nil
}

// Close releases the connection.
func (s *Store) Close() error { return s.conn.Close() }

// Ping reports whether the database answers.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.conn.Ping(ctx); err != nil {
		return safeerr.New("ping clickhouse", safeerr.CodeUnavailable, err)
	}
	return nil
}

func storageError(op string, err error) error {
	return safeerr.New(op, safeerr.CodeInternal, err)
}

// each runs a query in the tenant's scope and hands every row to decode. The
// error names what was read and the step that failed: the cause is dropped.
func (s *Store) each(ctx context.Context, tenantID uuid.UUID, what, query string, arguments []any, decode func(driver.Rows) error) error {
	rows, err := s.conn.Query(scoped(ctx, tenantID), query, arguments...)
	if err != nil {
		return storageError("query "+what, err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		if err := decode(rows); err != nil {
			return storageError("decode "+what, err)
		}
	}
	if err := rows.Err(); err != nil {
		return storageError("read "+what, err)
	}
	return nil
}

// collect is each that gathers one T per row.
func collect[T any](ctx context.Context, s *Store, tenantID uuid.UUID, what, query string, arguments []any, scan func(driver.Rows, *T) error) ([]T, error) {
	var result []T
	err := s.each(ctx, tenantID, what, query, arguments, func(rows driver.Rows) error {
		var item T
		if err := scan(rows, &item); err != nil {
			return err
		}
		result = append(result, item)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Insert returns after the server has written the block, so acknowledging the
// agent afterwards cannot lose events.
func (s *Store) Insert(ctx context.Context, events []audit.Event) error {
	if len(events) == 0 {
		return nil
	}
	batch, err := s.conn.PrepareBatch(ctx, `INSERT INTO audit_events (
		tenant_id, event_id, event_time, event_type, agent_id, source_id, database_principal,
		application_principal, application_id, identity_confidence, client_address, operation, tables,
		columns, column_ids, categories, query_fingerprint, execution_status, error_code, evidence_level,
		object_resolution, session_id, transaction_id, trace_id, gap_reason, gap_lost_events)`)
	if err != nil {
		return storageError("prepare event insert", err)
	}
	for i := range events {
		item := &events[i]
		err := batch.Append(item.TenantID, item.ID, item.Time, item.Type, item.AgentID, item.SourceID,
			item.DatabasePrincipal, item.ApplicationPrincipal, item.ApplicationID, item.IdentityConfidence,
			item.ClientAddress, item.Operation, orEmpty(item.Tables), orEmpty(item.Columns), orEmpty(item.ColumnIDs),
			orEmpty(item.Categories), item.QueryFingerprint, item.ExecutionStatus, item.ErrorCode, item.EvidenceLevel,
			item.ObjectResolution, item.SessionID, item.TransactionID, item.TraceID, item.GapReason, item.GapLostEvents)
		if err != nil {
			return errors.Join(storageError("append event", err), batch.Abort())
		}
	}
	if err := batch.Send(); err != nil {
		return storageError("insert events", err)
	}
	return nil
}

// Stored looks the keys up by the primary key. They travel as an external table,
// so a large batch does not become a large query text.
func (s *Store) Stored(ctx context.Context, tenantID uuid.UUID, keys []audit.EventKey) (map[uuid.UUID]bool, error) {
	stored := map[uuid.UUID]bool{}
	if len(keys) == 0 {
		return stored, nil
	}
	batch, err := ext.NewTable("batch_keys", ext.Column("event_time", "DateTime64(6, 'UTC')"), ext.Column("event_id", "UUID"))
	if err != nil {
		return nil, storageError("prepare event keys", err)
	}
	for _, key := range keys {
		if err := batch.Append(key.Time, key.ID); err != nil {
			return nil, storageError("append event key", err)
		}
	}
	ctx = clickhouse.Context(scoped(ctx, tenantID), clickhouse.WithExternalTable(batch))
	rows, err := s.conn.Query(ctx, `SELECT event_id FROM audit_events
		WHERE tenant_id = ? AND (event_time, event_id) IN (SELECT event_time, event_id FROM batch_keys)`, tenantID)
	if err != nil {
		return nil, storageError("look up stored events", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			return nil, storageError("decode stored event", err)
		}
		stored[id] = true
	}
	if err := rows.Err(); err != nil {
		return nil, storageError("read stored events", err)
	}
	return stored, nil
}

func orEmpty[T any](values []T) []T {
	if values == nil {
		return []T{}
	}
	return values
}

func scoped(ctx context.Context, tenantID uuid.UUID) context.Context {
	// The native protocol rejects a custom setting unless it is marked as one.
	return clickhouse.Context(ctx, clickhouse.WithSettings(clickhouse.Settings{
		tenantSetting: clickhouse.CustomSetting{Value: tenantID.String()},
	}))
}

const eventColumns = `event_id, event_time, event_type, agent_id, source_id, database_principal, application_principal,
	application_id, identity_confidence, client_address, operation, tables, columns, column_ids, categories,
	query_fingerprint, execution_status, error_code, evidence_level, object_resolution, session_id,
	transaction_id, trace_id, gap_reason, gap_lost_events`

// Search returns matching events, newest first, in key order, so it reads only as
// far as the requested page. The total is counted up to audit.CountLimit.
func (s *Store) Search(ctx context.Context, tenantID uuid.UUID, filter audit.Filter) ([]audit.Event, uint64, error) {
	ctx = scoped(ctx, tenantID)
	where, arguments := filterClause(tenantID, filter)
	var total uint64
	counted := `SELECT count() FROM (SELECT 1 FROM audit_events WHERE ` + where + ` LIMIT ?)`
	if err := s.conn.QueryRow(ctx, counted, append(slices.Clone(arguments), audit.CountLimit+1)...).Scan(&total); err != nil {
		return nil, 0, storageError("count events", err)
	}
	var events []audit.Event
	err := s.read(ctx, tenantID, where, arguments, filter.Limit, filter.Offset, func(event *audit.Event) error {
		events = append(events, *event)
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return events, total, nil
}

// Stream reads matching events in one pass, newest first, for an export that
// is larger than any page.
func (s *Store) Stream(ctx context.Context, tenantID uuid.UUID, filter audit.Filter, limit int, emit func(*audit.Event) error) error {
	where, arguments := filterClause(tenantID, filter)
	return s.read(scoped(ctx, tenantID), tenantID, where, arguments, limit, 0, emit)
}

// Count counts matching events up to limit; past it the exact number costs
// more than the answer is worth.
func (s *Store) Count(ctx context.Context, tenantID uuid.UUID, filter audit.Filter, limit int) (uint64, error) {
	where, arguments := filterClause(tenantID, filter)
	var total uint64
	counted := `SELECT count() FROM (SELECT 1 FROM audit_events WHERE ` + where + ` LIMIT ?)`
	if err := s.conn.QueryRow(scoped(ctx, tenantID), counted, append(arguments, limit)...).Scan(&total); err != nil {
		return 0, storageError("count events", err)
	}
	return total, nil
}

func (s *Store) read(ctx context.Context, tenantID uuid.UUID, where string, arguments []any, limit, offset int, emit func(*audit.Event) error) error {
	query := `SELECT ` + eventColumns + ` FROM audit_events WHERE ` + where + ` ORDER BY event_time DESC, event_id DESC LIMIT ? OFFSET ?`
	rows, err := s.conn.Query(ctx, query, append(slices.Clone(arguments), limit, offset)...)
	if err != nil {
		return storageError("search events", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		event := audit.Event{TenantID: tenantID}
		if err := rows.Scan(&event.ID, &event.Time, &event.Type, &event.AgentID, &event.SourceID,
			&event.DatabasePrincipal, &event.ApplicationPrincipal, &event.ApplicationID, &event.IdentityConfidence,
			&event.ClientAddress, &event.Operation, &event.Tables, &event.Columns, &event.ColumnIDs, &event.Categories,
			&event.QueryFingerprint, &event.ExecutionStatus, &event.ErrorCode, &event.EvidenceLevel,
			&event.ObjectResolution, &event.SessionID, &event.TransactionID, &event.TraceID, &event.GapReason,
			&event.GapLostEvents); err != nil {
			return storageError("decode event", err)
		}
		if err := emit(&event); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return storageError("read events", err)
	}
	return nil
}

func filterClause(tenantID uuid.UUID, filter audit.Filter) (string, []any) {
	conditions := []string{"tenant_id = ?", "event_time >= ?"}
	arguments := []any{tenantID, filter.From}
	add := func(condition string, value any) {
		conditions = append(conditions, condition)
		arguments = append(arguments, value)
	}
	if !filter.To.IsZero() {
		add("event_time < ?", filter.To)
	}
	if filter.SourceID != uuid.Nil {
		add("source_id = ?", filter.SourceID)
	}
	if filter.ColumnID != uuid.Nil {
		add("has(column_ids, toUUID(?))", filter.ColumnID.String())
	}
	if filter.Table != nil {
		conditions = append(conditions, tableCondition(filter.Table))
		arguments = append(arguments, filter.Table.Names)
		if len(filter.Table.ColumnIDs) > 0 {
			arguments = append(arguments, uuidStrings(filter.Table.ColumnIDs))
		}
	}
	if filter.Type != "" {
		add("event_type = ?", filter.Type)
	} else if filter.ExcludeType != "" {
		add("event_type != ?", filter.ExcludeType)
	}
	if filter.Category != "" {
		add("has(categories, ?)", filter.Category)
	}
	if filter.SessionID != "" {
		add("session_id = ?", filter.SessionID)
	}
	if clause, values := excluded(filter.ExcludeAccounts); clause != "" {
		conditions = append(conditions, clause)
		arguments = append(arguments, values...)
	}
	if filter.Principal != "" {
		conditions = append(conditions, "(database_principal = ? OR application_principal = ?)")
		arguments = append(arguments, filter.Principal, filter.Principal)
	}
	return strings.Join(conditions, " AND "), arguments
}

// excluded leaves out the given logins on their sources. It needs only
// source_id and database_principal, which the rows and the hourly projection
// both carry.
func excluded(accounts []audit.SourceAccount) (string, []any) {
	if len(accounts) == 0 {
		return "", nil
	}
	parts := make([]string, 0, len(accounts))
	values := make([]any, 0, 2*len(accounts))
	for _, account := range accounts {
		parts = append(parts, "NOT (source_id = ? AND database_principal = ?)")
		values = append(values, account.SourceID, account.Principal)
	}
	return strings.Join(parts, " AND "), values
}

// andExcluded is excluded as a suffix for a WHERE that already has a condition.
func andExcluded(accounts []audit.SourceAccount) (string, []any) {
	clause, values := excluded(accounts)
	if clause == "" {
		return "", nil
	}
	return " AND " + clause, values
}

func tableCondition(table *audit.TableMatch) string {
	if len(table.ColumnIDs) == 0 {
		return "hasAny(tables, ?)"
	}
	return "(hasAny(tables, ?) OR hasAny(column_ids, arrayMap(id -> toUUID(id), ?)))"
}

func uuidStrings(ids []uuid.UUID) []string {
	result := make([]string, len(ids))
	for i, id := range ids {
		result[i] = id.String()
	}
	return result
}

// facts is the shared body of the reports: events counted per hour and per
// dimension. Whole hours come from the hourly projection; the partial hours at
// the edges of the window come from the rows, so the result equals a count over
// the rows. The edge part names event_time, which the projection lacks, so it
// cannot be served from it by mistake. Excluded accounts are left out before
// grouping, which the projection can do since it keeps both columns. Each
// report groups by the dimensions it reads and no more: fewer groups, less
// to aggregate.
func facts(tenantID uuid.UUID, from, to time.Time, exclude []audit.SourceAccount, dimensions string) (string, []any) {
	firstHour := from.UTC().Truncate(time.Hour)
	if firstHour.Before(from) {
		firstHour = firstHour.Add(time.Hour)
	}
	lastHour := to.UTC().Truncate(time.Hour)
	if !firstHour.Before(lastHour) {
		firstHour, lastHour = to, to
	}
	exclusion, excludedValues := andExcluded(exclude)
	query := `SELECT ` + dimensions + `, count() AS events, max(event_time) AS last_event
		FROM audit_events
		WHERE tenant_id = ? AND toStartOfHour(event_time) >= ? AND toStartOfHour(event_time) < ?` + exclusion + `
		GROUP BY ` + dimensions + `
		UNION ALL
		SELECT ` + dimensions + `, count() AS events, max(event_time) AS last_event
		FROM audit_events
		WHERE tenant_id = ? AND ((event_time >= ? AND event_time < ?) OR (event_time >= ? AND event_time < ?))` + exclusion + `
		GROUP BY ` + dimensions
	arguments := append([]any{tenantID, firstHour, lastHour}, excludedValues...)
	arguments = append(arguments, tenantID, from, firstHour, lastHour, to)
	return query, append(arguments, excludedValues...)
}

// Dimensions of the reports, each a subset of the hourly projection's.
const (
	coverageDimensions = `source_id, database_principal, application_principal, identity_confidence,
		event_type, execution_status, object_resolution, categories`
	principalDimensions = `source_id, database_principal, application_principal, identity_confidence, event_type, categories`
	categoryDimensions  = `source_id, database_principal, application_principal, categories`
	summaryDimensions   = `database_principal, application_principal, event_type, execution_status, categories`
)

// columnFacts is facts for the events that read one column. The hourly
// projection does not keep columns, so these come from the rows.
func columnFacts(tenantID uuid.UUID, from, to time.Time, columnID uuid.UUID, exclude []audit.SourceAccount, dimensions string) (string, []any) {
	exclusion, excludedValues := andExcluded(exclude)
	query := `SELECT ` + dimensions + `, count() AS events, max(event_time) AS last_event
		FROM audit_events
		WHERE tenant_id = ? AND event_time >= ? AND event_time < ? AND has(column_ids, toUUID(?))` + exclusion + `
		GROUP BY ` + dimensions
	return query, append([]any{tenantID, from, to, columnID.String()}, excludedValues...)
}

// ByPrincipal groups by who acted. A row exists for each distinct way of being
// known, so an unverified claim never merges into a verified identity. The
// filter counts only the events that touched a category or read a column.
func (s *Store) ByPrincipal(ctx context.Context, tenantID uuid.UUID, from, to time.Time, filter audit.PrincipalFilter) ([]audit.PrincipalAccess, error) {
	body, arguments := facts(tenantID, from, to, filter.Exclude, principalDimensions)
	if filter.ColumnID != uuid.Nil {
		body, arguments = columnFacts(tenantID, from, to, filter.ColumnID, filter.Exclude, principalDimensions)
	}
	query := `SELECT database_principal, application_principal, identity_confidence, sum(events),
			sumIf(events, notEmpty(categories)), arraySort(groupUniqArrayArray(categories)), uniqExact(source_id), max(last_event)
		FROM (` + body + `)
		WHERE event_type NOT IN (?, ?) AND (? = '' OR has(categories, ?))
		GROUP BY database_principal, application_principal, identity_confidence
		ORDER BY sumIf(events, notEmpty(categories)) DESC, sum(events) DESC`
	arguments = append(arguments, typeGap, typeAuth, filter.Category, filter.Category)
	return collect(ctx, s, tenantID, "access by principal", query, arguments, func(rows driver.Rows, item *audit.PrincipalAccess) error {
		return rows.Scan(&item.DatabasePrincipal, &item.ApplicationPrincipal, &item.IdentityConfidence, &item.Events,
			&item.SensitiveEvents, &item.Categories, &item.Sources, &item.LastAccess)
	})
}

// ByCategory groups by data category.
func (s *Store) ByCategory(ctx context.Context, tenantID uuid.UUID, from, to time.Time, exclude []audit.SourceAccount) ([]audit.CategoryAccess, error) {
	body, arguments := facts(tenantID, from, to, exclude, categoryDimensions)
	query := `SELECT category, sum(events), uniqExact(database_principal, application_principal), uniqExact(source_id), max(last_event)
		FROM (` + body + `) ARRAY JOIN categories AS category
		GROUP BY category ORDER BY sum(events) DESC`
	return collect(ctx, s, tenantID, "access by category", query, arguments, func(rows driver.Rows, item *audit.CategoryAccess) error {
		return rows.Scan(&item.Category, &item.Events, &item.Principals, &item.Sources, &item.LastAccess)
	})
}

// Windows measures coverage per source. Logins are excluded: they name no objects,
// so counting them would inflate the share of resolved statements.
func (s *Store) Windows(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]audit.SourceWindow, error) {
	body, arguments := facts(tenantID, from, to, nil, coverageDimensions)
	query := `SELECT source_id,
			sumIf(events, event_type NOT IN (?, ?)),
			sumIf(events, event_type NOT IN (?, ?) AND object_resolution = ?),
			sumIf(events, event_type NOT IN (?, ?) AND identity_confidence = ?),
			sumIf(events, event_type NOT IN (?, ?) AND identity_confidence != ?),
			sumIf(events, event_type = ?),
			maxIf(last_event, event_type NOT IN (?, ?))
		FROM (` + body + `)
		GROUP BY source_id`
	arguments = append([]any{
		typeGap, typeAuth, typeGap, typeAuth, resolved, typeGap, typeAuth, confidenceVerified,
		typeGap, typeAuth, confidenceUnknown, typeGap, typeGap, typeAuth}, arguments...)
	return collect(ctx, s, tenantID, "coverage", query, arguments, func(rows driver.Rows, item *audit.SourceWindow) error {
		if err := rows.Scan(&item.SourceID, &item.Statements, &item.Resolved, &item.Verified, &item.Identified,
			&item.Gaps, &item.LastEvent); err != nil {
			return err
		}
		if item.Statements == 0 {
			item.LastEvent = time.Time{}
		}
		return nil
	})
}

// Summarize gives the headline numbers.
func (s *Store) Summarize(ctx context.Context, tenantID uuid.UUID, from, to time.Time, exclude []audit.SourceAccount) (audit.Summary, error) {
	body, arguments := facts(tenantID, from, to, exclude, summaryDimensions)
	query := `SELECT sumIf(events, event_type NOT IN (?, ?)), sumIf(events, notEmpty(categories)),
			sumIf(events, execution_status = ?), uniqExactIf((database_principal, application_principal), event_type != ?),
			sumIf(events, event_type = ?)
		FROM (` + body + `)`
	var summary audit.Summary
	err := s.conn.QueryRow(scoped(ctx, tenantID), query, append([]any{typeGap, typeAuth, statusFail, typeGap, typeGap}, arguments...)...).
		Scan(&summary.Events, &summary.SensitiveEvents, &summary.FailedEvents, &summary.Principals, &summary.Gaps)
	if err != nil {
		return audit.Summary{}, storageError("summarize events", err)
	}
	return summary, nil
}

// Timeline counts events per hour over whole hours: the first and the last
// hour of the window are counted in full. Grouping by the hour and the
// projection's dimensions lets ClickHouse answer from the hourly projection.
func (s *Store) Timeline(ctx context.Context, tenantID uuid.UUID, from, to time.Time, exclude []audit.SourceAccount) ([]audit.Hour, error) {
	first := from.UTC().Truncate(time.Hour)
	last := to.UTC().Truncate(time.Hour).Add(time.Hour)
	exclusion, excludedValues := andExcluded(exclude)
	query := `SELECT hour, sumIf(events, event_type NOT IN (?, ?)), sumIf(events, notEmpty(categories)), sumIf(events, execution_status = ?)
		FROM (
			SELECT toStartOfHour(event_time) AS hour, source_id, database_principal, event_type, execution_status, categories, count() AS events
			FROM audit_events
			WHERE tenant_id = ? AND toStartOfHour(event_time) >= ? AND toStartOfHour(event_time) < ?` + exclusion + `
			GROUP BY hour, source_id, database_principal, event_type, execution_status, categories
		)
		GROUP BY hour ORDER BY hour`
	arguments := append([]any{typeGap, typeAuth, statusFail, tenantID, first, last}, excludedValues...)
	return collect(ctx, s, tenantID, "events per hour", query, arguments, func(rows driver.Rows, hour *audit.Hour) error {
		return rows.Scan(&hour.Start, &hour.Events, &hour.SensitiveEvents, &hour.FailedEvents)
	})
}

// Activity counts events per principal and category in three windows at once,
// failures included, as the input of risk signals: the recent window from
// since, and two baselines ending at since. It reads the whole hours of the
// longest window once, from the hourly projection, and splits them by window.
// A row with an empty category is the principal's total: an event with two
// categories counts once there and once in each category row.
func (s *Store) Activity(ctx context.Context, tenantID uuid.UUID, windows audit.ActivityWindows, exclude []audit.SourceAccount) (audit.ActivityByWindow, error) {
	since := windows.Since.UTC().Truncate(time.Hour)
	week := since.Add(-windows.Week)
	month := since.Add(-windows.Month)
	exclusion, excludedValues := andExcluded(exclude)
	// The hourly rows are folded into three windows before the categories are
	// unrolled, so the ARRAY JOIN sees a few rows per principal, not one per hour.
	query := `SELECT database_principal, application_principal, identity_confidence, category,
			sumIf(events, span = 2), sumIf(events, span = 2 AND execution_status = ?), maxIf(last_event, span = 2),
			sumIf(events, span = 1), sumIf(events, span = 1 AND execution_status = ?),
			sumIf(events, span < 2)
		FROM (
			SELECT database_principal, application_principal, identity_confidence, execution_status, categories,
				multiIf(hour >= ?, 2, hour >= ?, 1, 0) AS span, sum(events) AS events, max(last_event) AS last_event
			FROM (
				SELECT database_principal, application_principal, identity_confidence, execution_status, categories,
					toStartOfHour(event_time) AS hour, count() AS events, max(event_time) AS last_event
				FROM audit_events
				WHERE tenant_id = ? AND toStartOfHour(event_time) >= ? AND event_type NOT IN (?, ?)` + exclusion + `
				GROUP BY database_principal, application_principal, identity_confidence, execution_status, categories, hour
			)
			GROUP BY database_principal, application_principal, identity_confidence, execution_status, categories, span
		)
		ARRAY JOIN arrayConcat([''], categories) AS category
		GROUP BY database_principal, application_principal, identity_confidence, category`
	arguments := append([]any{statusFail, statusFail, since, week, tenantID, month, typeGap, typeAuth}, excludedValues...)
	var result audit.ActivityByWindow
	err := s.each(ctx, tenantID, "activity", query, arguments, func(rows driver.Rows) error {
		var item audit.Activity
		var weekEvents, weekFailed, monthEvents uint64
		if err := rows.Scan(&item.DatabasePrincipal, &item.ApplicationPrincipal, &item.IdentityConfidence, &item.Category,
			&item.Events, &item.Failed, &item.LastEvent, &weekEvents, &weekFailed, &monthEvents); err != nil {
			return err
		}
		if item.Events > 0 {
			result.Recent = append(result.Recent, item)
		}
		if weekEvents > 0 {
			before := item
			before.Events, before.Failed = weekEvents, weekFailed
			result.Week = append(result.Week, before)
		}
		if monthEvents > 0 {
			before := item
			before.Events, before.Failed = monthEvents, 0
			result.Month = append(result.Month, before)
		}
		return nil
	})
	if err != nil {
		return audit.ActivityByWindow{}, err
	}
	return result, nil
}

// MatchPrincipals finds principals whose name contains the text, busiest
// first. It reads whole hours, which the hourly projection answers.
func (s *Store) MatchPrincipals(ctx context.Context, tenantID uuid.UUID, text string, since time.Time, exclude []audit.SourceAccount, limit int) ([]audit.PrincipalMatch, error) {
	exclusion, excludedValues := andExcluded(exclude)
	query := `SELECT database_principal, application_principal, sum(events)
		FROM (
			SELECT source_id, database_principal, application_principal, count() AS events
			FROM audit_events
			WHERE tenant_id = ? AND toStartOfHour(event_time) >= ? AND event_type NOT IN (?, ?)` + exclusion + `
			GROUP BY source_id, database_principal, application_principal
		)
		WHERE positionCaseInsensitiveUTF8(database_principal, ?) > 0 OR positionCaseInsensitiveUTF8(application_principal, ?) > 0
		GROUP BY database_principal, application_principal
		ORDER BY sum(events) DESC LIMIT ?`
	arguments := append([]any{tenantID, since.UTC().Truncate(time.Hour), typeGap, typeAuth}, excludedValues...)
	arguments = append(arguments, text, text, limit)
	return collect(ctx, s, tenantID, "principal matches", query, arguments, func(rows driver.Rows, item *audit.PrincipalMatch) error {
		return rows.Scan(&item.DatabasePrincipal, &item.ApplicationPrincipal, &item.Events)
	})
}

// ExecAdmin runs one administrative statement.
func ExecAdmin(ctx context.Context, settings Settings, statement string) error {
	conn, err := open(settings)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	return conn.Exec(ctx, statement)
}

// Migrate applies the embedded files with goose, as the schema owner, and grants
// the runtime user access to the database. ClickHouse DDL is not transactional:
// every file runs without a transaction, and a failed one must be fixed by hand
// before migrating again.
func Migrate(ctx context.Context, settings Settings, runtimeUser string, migrations fs.FS, directory string) error {
	files, err := fs.Sub(migrations, directory)
	if err != nil {
		return fmt.Errorf("open migrations: %w", err)
	}
	db := clickhouse.OpenDB(options(settings))
	defer func() { _ = db.Close() }()
	store, err := database.NewStore(database.DialectClickHouse, goose.DefaultTablename)
	if err != nil {
		return fmt.Errorf("prepare migrations: %w", err)
	}
	if err := adoptAppliedFiles(ctx, db, store); err != nil {
		return err
	}
	provider, err := goose.NewProvider(goose.DialectClickHouse, db, files, goose.WithIsolateDDL(true))
	if err != nil {
		return fmt.Errorf("prepare migrations: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	//nolint:gosec // GRANT takes no bind parameters; both names come from the server's configuration.
	grant := fmt.Sprintf("GRANT SELECT, INSERT ON %s.* TO %s", settings.Database, runtimeUser)
	if _, err := db.ExecContext(ctx, grant); err != nil {
		return fmt.Errorf("grant runtime user: %w", err)
	}
	return nil
}

// adoptAppliedFiles records in goose's table the files listed in
// schema_migrations, where databases migrated before goose keep them, and drops
// that table. Without it goose would apply them again: 0001 fails on the existing
// table, and 0002 rebuilds the event table.
func adoptAppliedFiles(ctx context.Context, db *sql.DB, store database.Store) error {
	var legacy uint64
	const find = `SELECT count() FROM system.tables WHERE database = currentDatabase() AND name = 'schema_migrations'`
	if err := db.QueryRowContext(ctx, find).Scan(&legacy); err != nil {
		return fmt.Errorf("look for applied migrations: %w", err)
	}
	if legacy == 0 {
		return nil
	}
	versions, err := appliedVersions(ctx, db)
	if err != nil {
		return err
	}
	if err := store.CreateVersionTable(ctx, db); err != nil {
		return fmt.Errorf("create migration table: %w", err)
	}
	// Version 0 is the row goose itself writes first; it marks the table as ready.
	for _, version := range append([]int64{0}, versions...) {
		_, err := store.GetMigration(ctx, db, version)
		if err == nil {
			continue
		}
		if !errors.Is(err, database.ErrVersionNotFound) {
			return fmt.Errorf("check migration %d: %w", version, err)
		}
		if err := store.Insert(ctx, db, database.InsertRequest{Version: version}); err != nil {
			return fmt.Errorf("record migration %d: %w", version, err)
		}
	}
	if _, err := db.ExecContext(ctx, `DROP TABLE schema_migrations`); err != nil {
		return fmt.Errorf("drop applied migrations: %w", err)
	}
	return nil
}

func appliedVersions(ctx context.Context, db *sql.DB) ([]int64, error) {
	rows, err := db.QueryContext(ctx, `SELECT name FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("read applied migrations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var versions []int64
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("read applied migration: %w", err)
		}
		version, err := goose.NumericComponent(name)
		if err != nil {
			return nil, fmt.Errorf("applied migration %s: %w", name, err)
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read applied migrations: %w", err)
	}
	return versions, nil
}
