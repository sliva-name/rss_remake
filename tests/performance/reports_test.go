//go:build performance

package performance_test

import (
	"fmt"
	"os"
	"slices"
	"strconv"
	"testing"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"

	"dataguard/internal/core/audit"
	"dataguard/internal/server/storage/clickhouse"
	"dataguard/internal/testkit/stand"
	"dataguard/migrations"
)

// Targets of ROADMAP.md, stage 0, for the reference volume: one tenant, 100
// million events over 30 days.
const (
	referenceEvents = 100_000_000
	referenceDays   = 30
	reportTarget    = time.Second
	searchTarget    = 300 * time.Millisecond
	exportTarget    = 10 * time.Second
	// Risk signals read 31 days to compare the last day with its baseline. The
	// server keeps the result for five minutes, so a reader waits at most once.
	signalsTarget = 2 * time.Second
	storeTarget   = 2_000 // events per second
	seedChunk     = 2_000_000
	runs          = 10
	storeBatch    = 1_000
	storeBatches  = 20
	// settleQuietPolls polls a second apart without a merge mean the seed is merged.
	settleQuietPolls = 3
	settleTimeout    = 15 * time.Minute
)

// seedEvents is synthetic: every value derives from the row number. Accounts are
// tied to sources and categories to tables, as in a real database, and a tenth of
// the rows belong to a second tenant that the reports must not count.
const seedEvents = `INSERT INTO audit_events (tenant_id, event_id, event_time, event_type, agent_id, source_id,
	database_principal, application_principal, application_id, identity_confidence, client_address, operation,
	tables, columns, column_ids, categories, query_fingerprint, execution_status, error_code, evidence_level,
	object_resolution, session_id, transaction_id, trace_id, gap_reason)
SELECT
	if(number %% 10 = 9, toUUID('%[1]s'), toUUID('%[2]s')),
	generateUUIDv4(number),
	now64(6) - toIntervalMicrosecond(intHash64(number) %% (%[3]d * 86400000000)),
	multiIf(kind < 70, 'EVENT_TYPE_DATA_ACCESS', kind < 90, 'EVENT_TYPE_DATA_MODIFICATION',
		kind < 97, 'EVENT_TYPE_AUTHENTICATION', kind < 99, 'EVENT_TYPE_FAILED_ACCESS', 'EVENT_TYPE_SCHEMA_CHANGE'),
	toUUID('00000000-0000-0000-0000-0000000000a1'),
	toUUID(concat('00000000-0000-0000-0000-0000000000', leftPad(toString(account %% 40), 2, '0'))),
	if(account < 6, concat('app_crm_', toString(account)), concat('svc_', toString(account))),
	if(account < 6, concat('employee-', toString(intHash32(number + 1) %% (1 + intHash32(number + 2) %% 3000))), ''),
	if(account < 6, 'crm', ''),
	multiIf(account < 6, 'IDENTITY_CONFIDENCE_VERIFIED', account = 59, 'IDENTITY_CONFIDENCE_UNKNOWN', 'IDENTITY_CONFIDENCE_DB_PRINCIPAL_ONLY'),
	concat('10.0.', toString(account), '.1'),
	if(kind < 70, 'OPERATION_TYPE_SELECT', 'OPERATION_TYPE_INSERT'),
	[concat('public.t', toString(tbl))],
	[concat('public.t', toString(tbl), '.c1'), concat('public.t', toString(tbl), '.c2')],
	[generateUUIDv4(tbl), generateUUIDv4(tbl + 1)],
	multiIf(tbl %% 5 = 0, ['PERSONAL.EMAIL', 'PERSONAL.PHONE'], tbl %% 7 = 0, ['GOVERNMENT.TAX_ID'], []),
	hex(intHash64(tbl * 10 + kind %% 10)),
	if(kind >= 97 AND kind < 99, 'EXECUTION_STATUS_FAILURE', 'EXECUTION_STATUS_SUCCESS'),
	'', 'EVIDENCE_LEVEL_EXECUTED',
	if(number %% 50 = 0, 'OBJECT_RESOLUTION_UNRESOLVED', 'OBJECT_RESOLUTION_RESOLVED'),
	toString(number %% 100000), toString(number), '', ''
FROM (SELECT number, number %% 100 AS kind, intHash32(number + 3) %% 60 AS account, intHash32(number + 4) %% 400 AS tbl
	FROM numbers_mt(%[4]d, %[5]d))`

func volume(t *testing.T) int {
	t.Helper()
	value := os.Getenv("DG_PERF_EVENTS")
	if value == "" {
		return referenceEvents
	}
	events, err := strconv.Atoi(value)
	if err != nil || events < seedChunk {
		t.Fatalf("DG_PERF_EVENTS must be a number of at least %d", seedChunk)
	}
	return events
}

func timed(t *testing.T, name string, target time.Duration, run func() error) {
	t.Helper()
	timedAfter(t, name, target, func() {}, run)
}

// timedCold measures a filtered query as a user's first try. ClickHouse
// remembers which parts of the table a filter excluded, so a repeated query
// skips them; the cache is dropped before every run to measure without it.
func timedCold(t *testing.T, owner clickhouse.Settings, name string, target time.Duration, run func() error) {
	t.Helper()
	timedAfter(t, name, target, func() {
		if err := clickhouse.ExecAdmin(t.Context(), owner, "SYSTEM DROP QUERY CONDITION CACHE"); err != nil {
			t.Fatalf("drop condition cache: %v", err)
		}
	}, run)
}

func timedAfter(t *testing.T, name string, target time.Duration, before func(), run func() error) {
	t.Helper()
	measured := make([]time.Duration, 0, runs)
	for range runs {
		before()
		started := time.Now()
		if err := run(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		measured = append(measured, time.Since(started))
	}
	slices.Sort(measured)
	p95 := percentile(measured, 0.95)
	t.Logf("%-12s p50 %s, p95 %s, target %s", name, percentile(measured, 0.5).Round(time.Millisecond), p95.Round(time.Millisecond), target)
	if p95 > target {
		t.Errorf("%s: p95 %s exceeds the target %s", name, p95.Round(time.Millisecond), target)
	}
}

func adminConnection(t *testing.T, owner clickhouse.Settings) chdriver.Conn {
	t.Helper()
	connection, err := chdriver.Open(&chdriver.Options{
		Addr: []string{owner.Address},
		Auth: chdriver.Auth{Database: owner.Database, Username: owner.Username, Password: owner.Password},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	return connection
}

// settle waits until the seeded parts are merged. Real events arrive over 30
// days and are merged long before anyone reads the month, while the seed lands
// in seconds; measured during its merges, a report times the cores the merges
// left over. One quiet poll is not enough: the next merge may not have started.
func settle(t *testing.T, connection chdriver.Conn) {
	t.Helper()
	started := time.Now()
	for quiet := 0; quiet < settleQuietPolls; {
		var merges, parts uint64
		err := connection.QueryRow(t.Context(), `SELECT
				(SELECT count() FROM system.merges WHERE database = currentDatabase() AND table = 'audit_events'),
				(SELECT count() FROM system.parts WHERE database = currentDatabase() AND table = 'audit_events' AND active)`).
			Scan(&merges, &parts)
		if err != nil {
			t.Fatal(err)
		}
		if merges > 0 {
			quiet = 0
		} else {
			quiet++
		}
		if time.Since(started) > settleTimeout {
			t.Fatalf("merges still running after %s, %d parts", settleTimeout, parts)
		}
		if quiet == settleQuietPolls {
			t.Logf("settled      %d parts after %s", parts, time.Since(started).Round(time.Second))
			return
		}
		time.Sleep(time.Second)
	}
}

// logStorage reports what the hourly projection costs next to the rows, because the
// ratio depends on how many accounts and identities act within an hour.
func logStorage(t *testing.T, connection chdriver.Conn) {
	t.Helper()
	var rows, projectionRows, bytes, projectionBytes uint64
	err := connection.QueryRow(t.Context(), `SELECT
			(SELECT sum(rows) FROM system.parts WHERE database = currentDatabase() AND table = 'audit_events' AND active),
			(SELECT sum(rows) FROM system.projection_parts WHERE database = currentDatabase() AND table = 'audit_events' AND active),
			(SELECT sum(data_compressed_bytes) FROM system.parts WHERE database = currentDatabase() AND table = 'audit_events' AND active),
			(SELECT sum(data_compressed_bytes) FROM system.projection_parts WHERE database = currentDatabase() AND table = 'audit_events' AND active)`).
		Scan(&rows, &projectionRows, &bytes, &projectionBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("storage      %d rows in %d MiB, hourly projection %d rows in %d MiB", rows, bytes>>20, projectionRows, projectionBytes>>20)
}

func TestReportsAndSearchAtReferenceVolume(t *testing.T) {
	ctx := t.Context()
	events := volume(t)
	owner, runtime := stand.EmptyCenterEvents(t)
	if err := clickhouse.Migrate(ctx, owner, runtime.Username, migrations.ClickHouse, "clickhouse"); err != nil {
		t.Fatal(err)
	}
	tenantID, otherTenant := uuid.New(), uuid.New()
	started := time.Now()
	for offset := 0; offset < events; offset += seedChunk {
		statement := fmt.Sprintf(seedEvents, otherTenant, tenantID, referenceDays, offset, min(seedChunk, events-offset))
		if err := clickhouse.ExecAdmin(ctx, owner, statement); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	t.Logf("seeded %d events in %s", events, time.Since(started).Round(time.Second))
	admin := adminConnection(t, owner)
	settle(t, admin)
	logStorage(t, admin)

	store, err := clickhouse.Open(ctx, runtime)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	to := time.Now()
	from := to.Add(-referenceDays * 24 * time.Hour)

	summary, err := store.Summarize(ctx, tenantID, from, to, nil)
	if err != nil {
		t.Fatal(err)
	}
	if summary.Events == 0 || summary.Events > uint64(events) {
		t.Fatalf("summary counted %d events of %d seeded", summary.Events, events)
	}

	// Reports leave out the scanner login of every source; a stand has five.
	scanners := make([]audit.SourceAccount, 0, 5)
	for account := range 5 {
		scanners = append(scanners, audit.SourceAccount{
			SourceID:  uuid.MustParse(fmt.Sprintf("00000000-0000-0000-0000-0000000000%02d", 10+account)),
			Principal: fmt.Sprintf("svc_%d", 10+account),
		})
	}
	timed(t, "summary", reportTarget, func() error { _, err := store.Summarize(ctx, tenantID, from, to, scanners); return err })
	timed(t, "principals", reportTarget, func() error {
		_, err := store.ByPrincipal(ctx, tenantID, from, to, audit.PrincipalFilter{Exclude: scanners})
		return err
	})
	timed(t, "timeline", reportTarget, func() error { _, err := store.Timeline(ctx, tenantID, from, to, scanners); return err })
	timed(t, "categories", reportTarget, func() error { _, err := store.ByCategory(ctx, tenantID, from, to, scanners); return err })
	timed(t, "coverage", reportTarget, func() error { _, err := store.Windows(ctx, tenantID, from, to); return err })
	timedCold(t, owner, "search", searchTarget, func() error {
		_, _, err := store.Search(ctx, tenantID, audit.Filter{
			From: from, To: to, Limit: 50, ExcludeType: "EVENT_TYPE_AUTHENTICATION",
		})
		return err
	})

	// Object pages and investigations. The seeded column IDs are random, so the
	// column filters match nothing and read the whole window: the worst case.
	unknownColumn := uuid.New()
	timedCold(t, owner, "by table", searchTarget, func() error {
		_, _, err := store.Search(ctx, tenantID, audit.Filter{
			From: from, To: to, Limit: 50, Table: &audit.TableMatch{Names: []string{"public.t5"}, ColumnIDs: []uuid.UUID{unknownColumn}},
		})
		return err
	})
	timedCold(t, owner, "by column", searchTarget, func() error {
		_, _, err := store.Search(ctx, tenantID, audit.Filter{From: from, To: to, Limit: 50, ColumnID: unknownColumn})
		return err
	})
	weekAgo := to.Add(-7 * 24 * time.Hour)
	timedCold(t, owner, "column read", reportTarget, func() error {
		_, err := store.ByPrincipal(ctx, tenantID, weekAgo, to, audit.PrincipalFilter{ColumnID: unknownColumn, Exclude: scanners})
		return err
	})
	timed(t, "signals", signalsTarget, func() error {
		_, err := store.Activity(ctx, tenantID, audit.ActivityWindows{Since: to.Add(-24 * time.Hour), Week: 7 * 24 * time.Hour, Month: 30 * 24 * time.Hour}, scanners)
		return err
	})
	timedCold(t, owner, "principal q", searchTarget, func() error {
		_, err := store.MatchPrincipals(ctx, tenantID, "crm_3", from, scanners, 8)
		return err
	})
	exported := 0
	timed(t, "export 100k", exportTarget, func() error {
		exported = 0
		return store.Stream(ctx, tenantID, audit.Filter{From: from, To: to, ExcludeType: "EVENT_TYPE_AUTHENTICATION"}, 100_000, func(*audit.Event) error {
			exported++
			return nil
		})
	})
	if exported != 100_000 {
		t.Errorf("export streamed %d events, want 100000", exported)
	}

	stored, elapsed := 0, time.Duration(0)
	for batch := range storeBatches {
		items := make([]audit.Event, storeBatch)
		keys := make([]audit.EventKey, storeBatch)
		for i := range items {
			items[i] = audit.Event{
				ID: uuid.New(), TenantID: tenantID, SourceID: uuid.New(), Type: "EVENT_TYPE_DATA_ACCESS",
				Time:              time.Now().UTC().Truncate(time.Microsecond),
				DatabasePrincipal: fmt.Sprintf("svc_%d", batch), IdentityConfidence: "IDENTITY_CONFIDENCE_DB_PRINCIPAL_ONLY",
			}
			keys[i] = audit.EventKey{Time: items[i].Time, ID: items[i].ID}
		}
		began := time.Now()
		if _, err := store.Stored(ctx, tenantID, keys); err != nil {
			t.Fatal(err)
		}
		if err := store.Insert(ctx, items); err != nil {
			t.Fatal(err)
		}
		elapsed += time.Since(began)
		stored += storeBatch
		found, err := store.Stored(ctx, tenantID, keys)
		if err != nil || len(found) != storeBatch {
			t.Fatalf("a stored batch must be found again: %d of %d, %v", len(found), storeBatch, err)
		}
	}
	rate := float64(stored) / elapsed.Seconds()
	t.Logf("store        %.0f events/s in batches of %d, check and insert, target %d", rate, storeBatch, storeTarget)
	if rate < storeTarget {
		t.Errorf("store: %.0f events/s is below the target %d", rate, storeTarget)
	}
}
