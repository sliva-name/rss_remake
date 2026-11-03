// Package clickhouse stores audit events. Reads go through two independent locks:
// the query filters by tenant, and the row policy on the server filters by the
// session setting.
package clickhouse

import (
	"context"
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

func open(settings Settings) (driver.Conn, error) {
	return clickhouse.Open(&clickhouse.Options{
		Addr:        []string{settings.Address},
		Auth:        clickhouse.Auth{Database: settings.Database, Username: settings.Username, Password: settings.Password},
		DialTimeout: dialTimeout, ReadTimeout: readTimeout,
	})
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
	query := `SELECT ` + eventColumns + ` FROM audit_events WHERE ` + where + ` ORDER BY event_time DESC, event_id DESC LIMIT ? OFFSET ?`
	rows, err := s.conn.Query(ctx, query, append(arguments, filter.Limit, filter.Offset)...)
	if err != nil {
		return nil, 0, storageError("search events", err)
	}
	defer func() { _ = rows.Close() }()

	var events []audit.Event
	for rows.Next() {
		event := audit.Event{TenantID: tenantID}
		if err := rows.Scan(&event.ID, &event.Time, &event.Type, &event.AgentID, &event.SourceID,
			&event.DatabasePrincipal, &event.ApplicationPrincipal, &event.ApplicationID, &event.IdentityConfidence,
			&event.ClientAddress, &event.Operation, &event.Tables, &event.Columns, &event.ColumnIDs, &event.Categories,
			&event.QueryFingerprint, &event.ExecutionStatus, &event.ErrorCode, &event.EvidenceLevel,
			&event.ObjectResolution, &event.SessionID, &event.TransactionID, &event.TraceID, &event.GapReason,
			&event.GapLostEvents); err != nil {
			return nil, 0, storageError("decode event", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, storageError("read events", err)
	}
	return events, total, nil
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
	if filter.Type != "" {
		add("event_type = ?", filter.Type)
	} else if filter.ExcludeType != "" {
		add("event_type != ?", filter.ExcludeType)
	}
	if filter.Category != "" {
		add("has(categories, ?)", filter.Category)
	}
	for _, account := range filter.ExcludeAccounts {
		conditions = append(conditions, "NOT (source_id = ? AND database_principal = ?)")
		arguments = append(arguments, account.SourceID, account.Principal)
	}
	if filter.Principal != "" {
		conditions = append(conditions, "(database_principal = ? OR application_principal = ?)")
		arguments = append(arguments, filter.Principal, filter.Principal)
	}
	return strings.Join(conditions, " AND "), arguments
}

// facts is the shared body of the reports: events counted per hour and per
// dimension. Whole hours come from the hourly projection; the partial hours at
// the edges of the window come from the rows, so the result equals a count over
// the rows. The edge part names event_time, which the projection lacks, so it
// cannot be served from it by mistake.
func facts(tenantID uuid.UUID, from, to time.Time) (string, []any) {
	const dimensions = `source_id, database_principal, application_principal, identity_confidence,
		event_type, execution_status, object_resolution, categories`
	firstHour := from.UTC().Truncate(time.Hour)
	if firstHour.Before(from) {
		firstHour = firstHour.Add(time.Hour)
	}
	lastHour := to.UTC().Truncate(time.Hour)
	if !firstHour.Before(lastHour) {
		firstHour, lastHour = to, to
	}
	query := `SELECT ` + dimensions + `, count() AS events, max(event_time) AS last_event
		FROM audit_events
		WHERE tenant_id = ? AND toStartOfHour(event_time) >= ? AND toStartOfHour(event_time) < ?
		GROUP BY ` + dimensions + `
		UNION ALL
		SELECT ` + dimensions + `, count() AS events, max(event_time) AS last_event
		FROM audit_events
		WHERE tenant_id = ? AND ((event_time >= ? AND event_time < ?) OR (event_time >= ? AND event_time < ?))
		GROUP BY ` + dimensions
	return query, []any{tenantID, firstHour, lastHour, tenantID, from, firstHour, lastHour, to}
}

// ByPrincipal groups by who acted. A row exists for each distinct way of being
// known, so an unverified claim never merges into a verified identity.
func (s *Store) ByPrincipal(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]audit.PrincipalAccess, error) {
	body, arguments := facts(tenantID, from, to)
	query := `SELECT database_principal, application_principal, identity_confidence, sum(events),
			sumIf(events, notEmpty(categories)), arraySort(groupUniqArrayArray(categories)), uniqExact(source_id), max(last_event)
		FROM (` + body + `)
		WHERE event_type NOT IN (?, ?)
		GROUP BY database_principal, application_principal, identity_confidence
		ORDER BY sumIf(events, notEmpty(categories)) DESC, sum(events) DESC`
	rows, err := s.conn.Query(scoped(ctx, tenantID), query, append(arguments, typeGap, typeAuth)...)
	if err != nil {
		return nil, storageError("group by principal", err)
	}
	defer func() { _ = rows.Close() }()
	var result []audit.PrincipalAccess
	for rows.Next() {
		var item audit.PrincipalAccess
		if err := rows.Scan(&item.DatabasePrincipal, &item.ApplicationPrincipal, &item.IdentityConfidence, &item.Events,
			&item.SensitiveEvents, &item.Categories, &item.Sources, &item.LastAccess); err != nil {
			return nil, storageError("decode principal", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, storageError("read principals", err)
	}
	return result, nil
}

// ByCategory groups by data category.
func (s *Store) ByCategory(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]audit.CategoryAccess, error) {
	body, arguments := facts(tenantID, from, to)
	query := `SELECT category, sum(events), uniqExact(database_principal, application_principal), uniqExact(source_id), max(last_event)
		FROM (` + body + `) ARRAY JOIN categories AS category
		GROUP BY category ORDER BY sum(events) DESC`
	rows, err := s.conn.Query(scoped(ctx, tenantID), query, arguments...)
	if err != nil {
		return nil, storageError("group by category", err)
	}
	defer func() { _ = rows.Close() }()
	var result []audit.CategoryAccess
	for rows.Next() {
		var item audit.CategoryAccess
		if err := rows.Scan(&item.Category, &item.Events, &item.Principals, &item.Sources, &item.LastAccess); err != nil {
			return nil, storageError("decode category", err)
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, storageError("read categories", err)
	}
	return result, nil
}

// Windows measures coverage per source. Logins are excluded: they name no objects,
// so counting them would inflate the share of resolved statements.
func (s *Store) Windows(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]audit.SourceWindow, error) {
	body, arguments := facts(tenantID, from, to)
	query := `SELECT source_id,
			sumIf(events, event_type NOT IN (?, ?)),
			sumIf(events, event_type NOT IN (?, ?) AND object_resolution = ?),
			sumIf(events, event_type NOT IN (?, ?) AND identity_confidence = ?),
			sumIf(events, event_type NOT IN (?, ?) AND identity_confidence != ?),
			sumIf(events, event_type = ?),
			maxIf(last_event, event_type NOT IN (?, ?))
		FROM (` + body + `)
		GROUP BY source_id`
	rows, err := s.conn.Query(scoped(ctx, tenantID), query, append([]any{
		typeGap, typeAuth, typeGap, typeAuth, resolved, typeGap, typeAuth, confidenceVerified,
		typeGap, typeAuth, confidenceUnknown, typeGap, typeGap, typeAuth}, arguments...)...)
	if err != nil {
		return nil, storageError("measure coverage", err)
	}
	defer func() { _ = rows.Close() }()
	var result []audit.SourceWindow
	for rows.Next() {
		var item audit.SourceWindow
		if err := rows.Scan(&item.SourceID, &item.Statements, &item.Resolved, &item.Verified, &item.Identified,
			&item.Gaps, &item.LastEvent); err != nil {
			return nil, storageError("decode coverage", err)
		}
		if item.Statements == 0 {
			item.LastEvent = time.Time{}
		}
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		return nil, storageError("read coverage", err)
	}
	return result, nil
}

// Summarize gives the headline numbers.
func (s *Store) Summarize(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (audit.Summary, error) {
	body, arguments := facts(tenantID, from, to)
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

// ExecAdmin runs one administrative statement.
func ExecAdmin(ctx context.Context, settings Settings, statement string) error {
	conn, err := open(settings)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	return conn.Exec(ctx, statement)
}

const migrationsTable = `CREATE TABLE IF NOT EXISTS schema_migrations
	(name String, applied_at DateTime DEFAULT now()) ENGINE = MergeTree ORDER BY name`

// Migrate applies embedded files in name order, as the schema owner, and grants the
// runtime user access to the database. ClickHouse DDL is not transactional, so a
// failed file must be fixed by hand before migrating again.
func Migrate(ctx context.Context, settings Settings, runtimeUser string, migrations fs.FS, directory string) error {
	conn, err := open(settings)
	if err != nil {
		return fmt.Errorf("open migration connection: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Exec(ctx, migrationsTable); err != nil {
		return fmt.Errorf("prepare migrations: %w", err)
	}
	entries, err := fs.ReadDir(migrations, directory)
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	slices.Sort(names)
	for _, name := range names {
		if err := applyMigration(ctx, conn, migrations, directory, name); err != nil {
			return err
		}
	}
	grant := fmt.Sprintf("GRANT SELECT, INSERT ON %s.* TO %s", settings.Database, runtimeUser)
	if err := conn.Exec(ctx, grant); err != nil {
		return fmt.Errorf("grant runtime user: %w", err)
	}
	return nil
}

func applyMigration(ctx context.Context, conn driver.Conn, migrations fs.FS, directory, name string) error {
	var applied uint64
	if err := conn.QueryRow(ctx, `SELECT count() FROM schema_migrations WHERE name = ?`, name).Scan(&applied); err != nil {
		return fmt.Errorf("check migration %s: %w", name, err)
	}
	if applied > 0 {
		return nil
	}
	content, err := fs.ReadFile(migrations, directory+"/"+name)
	if err != nil {
		return fmt.Errorf("read migration %s: %w", name, err)
	}
	for statement := range strings.SplitSeq(withoutComments(string(content)), ";") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if err := conn.Exec(ctx, statement); err != nil {
			return fmt.Errorf("apply migration %s: %w", name, err)
		}
	}
	if err := conn.Exec(ctx, `INSERT INTO schema_migrations (name) VALUES (?)`, name); err != nil {
		return fmt.Errorf("record migration %s: %w", name, err)
	}
	return nil
}

// withoutComments drops comment lines first, so a semicolon in a comment does not
// split a statement. Migrations must not use semicolons inside string literals.
func withoutComments(content string) string {
	var kept []string
	for line := range strings.SplitSeq(content, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			kept = append(kept, line)
		}
	}
	return strings.Join(kept, "\n")
}
