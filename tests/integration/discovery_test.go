//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"dataguard/internal/agent/config"
	"dataguard/internal/agent/queue"
	"dataguard/internal/agent/runtime"
	"dataguard/internal/agent/sources"
	"dataguard/internal/classifier"
	"dataguard/internal/core/asset"
	"dataguard/internal/core/fleet"
	"dataguard/internal/core/scan"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/safelog"
	"dataguard/internal/platform/sealing"
	"dataguard/internal/testkit/seed"
	"dataguard/internal/testkit/stand"
	"dataguard/internal/testkit/synthetic"
)

const seededRows = 120

type lockedBuffer struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (b *lockedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.Write(data)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buffer.String()
}

type runningAgent struct {
	logs   *lockedBuffer
	audit  *runtime.Audit
	events *queue.Queue
}

// addSource defines a source the way an administrator does: the password is
// sealed to the agent's key before it reaches the center.
func (p *platform) addSource(t *testing.T, enrolled enrolledAgent, definition sources.Definition) uuid.UUID {
	t.Helper()
	tenantID, agentID := enrolled.store.TenantID(), enrolled.store.AgentID()
	sealed, err := sealing.Seal(enrolled.store.SealingKey().PublicKey().Bytes(), sealing.Binding{
		TenantID: tenantID, AgentID: agentID, Engine: definition.Engine, Host: definition.Host, Port: definition.Port,
		Database: definition.Database, Username: definition.Username, TLS: definition.TLS,
	}, []byte(definition.Password))
	if err != nil {
		t.Fatal(err)
	}
	created, err := p.app.Fleet.CreateSource(context.Background(), tenantID, fleet.Source{
		Key: definition.Name, AgentID: agentID, Engine: definition.Engine, Host: definition.Host, Port: definition.Port,
		Database: definition.Database, Username: definition.Username, TLS: definition.TLS,
		AuditDirectory: definition.AuditDirectory, MaxConnections: definition.MaxConnections, SealedPassword: sealed,
	})
	if err != nil {
		t.Fatalf("CreateSource: %v", err)
	}
	return created.ID
}

// placeholderSource is enough for tests that drive the agent RPC by hand.
func placeholderSource() sources.Definition {
	return sources.Definition{
		Name: "crm", Engine: sources.EnginePostgreSQL, Host: "db.invalid", Port: 5432, Database: "crm",
		Username: "dg_scanner", Password: "synthetic-password", TLS: "disable",
	}
}

// testAllowlist lets the agent reach the stand on loopback and read its audit logs.
func testAllowlist(t *testing.T) *config.Allowlist {
	t.Helper()
	allowlist, err := config.CompileAllowed(config.Allowed{
		Hosts:            []string{"127.0.0.1"},
		AuditDirectories: []string{filepath.Dir(stand.AuditDirectory("postgresql"))},
	})
	if err != nil {
		t.Fatal(err)
	}
	return allowlist
}

// startAgent defines the sources in the center and runs the real control,
// discovery and audit loops, which fetch them from the signed list.
func (p *platform) startAgent(t *testing.T, enrolled enrolledAgent, definitions ...sources.Definition) (*runningAgent, []uuid.UUID) {
	t.Helper()
	ids := make([]uuid.UUID, 0, len(definitions))
	for _, definition := range definitions {
		ids = append(ids, p.addSource(t, enrolled, definition))
	}
	logs := &lockedBuffer{}
	logger := safelog.New(logs, slog.LevelDebug)
	registry := sources.NewRegistry()
	t.Cleanup(func() { _ = registry.Close() })

	events, err := queue.Open(enrolled.dir, 1<<24)
	if err != nil {
		t.Fatalf("queue.Open: %v", err)
	}
	t.Cleanup(func() { _ = events.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	sourceSync := &runtime.SourceSync{
		Registry: registry, Allowlist: testAllowlist(t), Key: enrolled.store.SealingKey(),
		TenantID: enrolled.store.TenantID(), AgentID: enrolled.store.AgentID(), Logger: logger,
	}
	discovery := runtime.NewDiscovery(enrolled.client, registry, 100*time.Millisecond, logger)
	audit := runtime.NewAudit(enrolled.client, registry, events, nil, logger)
	control := runtime.NewControl(runtime.Options{
		Client: enrolled.client, Identity: enrolled.store, Prober: registry, Sources: sourceSync, Health: audit,
		Policies: discovery, Version: "test", HeartbeatInterval: 200 * time.Millisecond, Logger: logger,
	})
	var running sync.WaitGroup
	running.Go(func() { control.Run(ctx) })
	running.Go(func() { discovery.Run(ctx) })
	running.Go(func() { audit.Run(ctx) })
	t.Cleanup(func() {
		cancel()
		running.Wait()
	})
	for _, id := range ids {
		waitForProbe(t, p, enrolled.store.TenantID(), id)
	}
	return &runningAgent{logs: logs, audit: audit, events: events}, ids
}

// waitForProbe waits until the agent has opened the source and reported on it.
func waitForProbe(t *testing.T, platform *platform, tenantID, sourceID uuid.UUID) fleet.Source {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		found, err := platform.app.Fleet.ListSources(context.Background(), tenantID)
		if err != nil {
			t.Fatal(err)
		}
		for _, source := range found {
			if source.ID == sourceID && source.ProbedAt != nil {
				return source
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("source %s was not probed", sourceID)
	return fleet.Source{}
}

func waitForScan(t *testing.T, platform *platform, tenantID, jobID uuid.UUID) scan.Job {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		jobs, err := platform.app.Scans.List(context.Background(), tenantID, 50)
		if err != nil {
			t.Fatal(err)
		}
		for _, job := range jobs {
			if job.ID == jobID && job.FinishedAt != nil {
				return job
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("scan did not finish")
	return scan.Job{}
}

func TestDiscoveryOnEveryEngine(t *testing.T) {
	for _, source := range stand.AllSources(t) {
		t.Run(source.Dialect.Name, func(t *testing.T) {
			ctx := context.Background()
			if err := seed.Tables(ctx, source.Admin, source.Dialect, seededRows, synthetic.New(11)); err != nil {
				t.Fatalf("seed: %v", err)
			}
			platform := startPlatform(t)
			created, environment := platform.newTenant(t, "Acme")
			enrolled := platform.enroll(t, created.ID, environment.ID)
			agent, ids := platform.startAgent(t, enrolled, source.Config)
			sourceID := ids[0]
			job, err := platform.app.Scans.Request(ctx, created.ID, sourceID, "tester")
			if err != nil {
				t.Fatalf("Request: %v", err)
			}
			finished := waitForScan(t, platform, created.ID, job.ID)
			if finished.Status != scan.StatusCompleted {
				t.Fatalf("scan finished as %s (%s); logs: %s", finished.Status, finished.FailureCode, agent.logs.String())
			}

			entries, total, err := platform.store.ListCatalog(ctx, created.ID, asset.CatalogFilter{Limit: 500})
			if err != nil {
				t.Fatalf("ListCatalog: %v", err)
			}
			if total != int64(len(entries)) {
				t.Fatalf("total %d for %d entries", total, len(entries))
			}
			found := map[string]asset.CatalogEntry{}
			for _, entry := range entries {
				found[entry.Table+"."+entry.Column+"="+entry.CategoryID] = entry
			}
			for _, want := range []string{
				seed.Users + ".email=" + classifier.CategoryEmail,
				seed.Users + ".phone=" + classifier.CategoryPhone,
				seed.Users + ".inn=" + classifier.CategoryTaxID,
				seed.Users + ".snils=" + classifier.CategorySNILS,
				seed.Users + ".card_number=" + classifier.CategoryPaymentCard,
				seed.Users + ".passport=" + classifier.CategoryPassport,
				seed.Users + ".first_name=" + classifier.CategoryPersonName,
			} {
				if _, ok := found[want]; !ok {
					t.Errorf("not classified: %s; got %v", want, keys(found))
				}
			}
			for key := range found {
				if strings.HasPrefix(key, seed.Orders+".") || strings.HasPrefix(key, seed.Users+".status") {
					t.Errorf("false positive: %s", key)
				}
			}
			if entry := found[seed.Users+".email="+classifier.CategoryEmail]; entry.RowsMatched == 0 || entry.UniqueEstimate == 0 {
				t.Errorf("aggregates missing: %+v", entry)
			}
			reports, err := platform.app.Fleet.ListSources(ctx, created.ID)
			if err != nil {
				t.Fatal(err)
			}
			if len(reports) != 1 || reports[0].EngineVersion == "" {
				t.Fatalf("source report: %+v", reports)
			}
			platform.assertNoValuesInCenter(t)
			if strings.Contains(agent.logs.String(), synthetic.CanaryMarker) {
				t.Fatal("agent logs contain a synthetic value")
			}
			wire := platform.gate.recorded()
			if len(wire) == 0 {
				t.Fatal("nothing was recorded, the wire check proves nothing")
			}
			for _, value := range sourceValues(t, source) {
				if bytes.Contains(wire, []byte(value)) {
					t.Fatal("a source value crossed the wire")
				}
			}
		})
	}
}

func mustUUID(t *testing.T, value string) uuid.UUID {
	t.Helper()
	parsed, err := uuid.Parse(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// sourceValues reads the sensitive values actually stored in the seeded table.
func sourceValues(t *testing.T, source stand.Source) []string {
	t.Helper()
	rows, err := source.Admin.Query(`SELECT email, phone, inn, snils, card_number, passport FROM ` + seed.Users)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var values []string
	for rows.Next() {
		row := make([]string, 6)
		if err := rows.Scan(&row[0], &row[1], &row[2], &row[3], &row[4], &row[5]); err != nil {
			t.Fatal(err)
		}
		values = append(values, row...)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(values) == 0 {
		t.Fatal("no values to search for")
	}
	return values
}

func keys(found map[string]asset.CatalogEntry) []string {
	result := make([]string, 0, len(found))
	for key := range found {
		result = append(result, key)
	}
	return result
}

// assertNoValuesInCenter reads every column of every table as text. A marker
// anywhere in the central database means a value crossed the boundary.
func (p *platform) assertNoValuesInCenter(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	connection, err := pgx.Connect(ctx, p.ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close(ctx) }()
	rows, err := connection.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = 'public'`)
	if err != nil {
		t.Fatal(err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	if len(tables) < 10 {
		t.Fatalf("expected the whole schema, saw %v", tables)
	}
	for _, table := range tables {
		query := fmt.Sprintf(`SELECT count(*) FROM %s t WHERE t::text LIKE '%%' || $1 || '%%'`, pgx.Identifier{table}.Sanitize())
		var matches int
		if err := connection.QueryRow(ctx, query, synthetic.CanaryMarker).Scan(&matches); err != nil {
			t.Fatalf("search %s: %v", table, err)
		}
		if matches != 0 {
			t.Errorf("table %s holds %d rows with a synthetic value", table, matches)
		}
	}
}

func TestRescanTracksRenameAndRemoval(t *testing.T) {
	ctx := context.Background()
	source := stand.PostgresSource(t)
	if err := seed.Tables(ctx, source.Admin, source.Dialect, seededRows, synthetic.New(5)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	_, ids := platform.startAgent(t, platform.enroll(t, created.ID, environment.ID), source.Config)
	sourceID := ids[0]

	runScan := func() {
		t.Helper()
		job, err := platform.app.Scans.Request(ctx, created.ID, sourceID, "tester")
		if err != nil {
			t.Fatal(err)
		}
		if finished := waitForScan(t, platform, created.ID, job.ID); finished.Status != scan.StatusCompleted {
			t.Fatalf("scan: %+v", finished)
		}
	}
	columnID := func(column string) string {
		t.Helper()
		entries, _, err := platform.store.ListCatalog(ctx, created.ID, asset.CatalogFilter{Limit: 500})
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.Table == seed.Users && entry.Column == column {
				return entry.ColumnID.String()
			}
		}
		return ""
	}

	runScan()
	before := columnID("email")
	if before == "" {
		t.Fatal("email not classified")
	}

	for _, statement := range []string{
		`ALTER TABLE dg_users RENAME COLUMN email TO email_address`,
		`ALTER TABLE dg_users DROP COLUMN snils`,
	} {
		if _, err := source.Admin.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	runScan()

	if after := columnID("email_address"); after != before {
		t.Fatalf("rename lost identity: %s then %s", before, after)
	}
	if columnID("snils") != "" {
		t.Fatal("removed column still listed as sensitive")
	}
	history, err := platform.store.ListHistory(ctx, created.ID, 200)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, entry := range history {
		seen[entry.Kind] = true
	}
	for _, kind := range []string{asset.ChangeColumnRenamed, asset.ChangeColumnRemoved, asset.ChangeSensitiveAdded, asset.ChangeSchemaDrift} {
		if !seen[kind] {
			t.Errorf("history has no %s: %v", kind, seen)
		}
	}
}

func TestDuplicateResultIsRefused(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	enrolled := platform.enroll(t, created.ID, environment.ID)
	sourceID := platform.addSource(t, enrolled, placeholderSource()).String()
	job, err := platform.app.Scans.Request(ctx, created.ID, mustUUID(t, sourceID), "tester")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := enrolled.client.PullJobs(ctx, 1); err != nil {
		t.Fatal(err)
	}
	result := &agentv1.ScanResult{
		JobId: job.ID.String(), SourceId: sourceID, Outcome: agentv1.ScanOutcome_SCAN_OUTCOME_FAILED, FailureCode: "UNAVAILABLE",
	}
	if err := enrolled.client.SubmitScanResult(ctx, result); err != nil {
		t.Fatalf("first submit: %v", err)
	}
	if err := enrolled.client.SubmitScanResult(ctx, result); err == nil {
		t.Fatal("a duplicate result must be refused")
	}
}

func TestFailedScanDoesNotEraseCatalog(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	enrolled := platform.enroll(t, created.ID, environment.ID)
	sourceID := platform.addSource(t, enrolled, placeholderSource()).String()
	submit := func(result *agentv1.ScanResult) {
		t.Helper()
		job, err := platform.app.Scans.Request(ctx, created.ID, mustUUID(t, sourceID), "tester")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := enrolled.client.PullJobs(ctx, 1); err != nil {
			t.Fatal(err)
		}
		result.JobId, result.SourceId = job.ID.String(), sourceID
		if err := enrolled.client.SubmitScanResult(ctx, result); err != nil {
			t.Fatalf("submit: %v", err)
		}
	}
	path := &agentv1.TablePath{Database: "crm", Schema: "public", Table: "users"}
	submit(&agentv1.ScanResult{
		Outcome: agentv1.ScanOutcome_SCAN_OUTCOME_COMPLETED,
		Tables: []*agentv1.TableSnapshot{{
			Path: path, Kind: agentv1.TableKind_TABLE_KIND_TABLE,
			Columns: []*agentv1.ColumnSnapshot{{Name: "email", NativeType: "text", Ordinal: 1}},
		}},
		Classifications: []*agentv1.ColumnClassification{{
			Column: &agentv1.ColumnPath{Table: path, Column: "email"}, CategoryId: classifier.CategoryEmail, Confidence: 0.9,
			Evidence: &agentv1.ClassificationEvidence{}, Profile: &agentv1.ColumnProfile{},
		}},
	})
	submit(&agentv1.ScanResult{Outcome: agentv1.ScanOutcome_SCAN_OUTCOME_FAILED, FailureCode: "UNAVAILABLE"})

	entries, _, err := platform.store.ListCatalog(ctx, created.ID, asset.CatalogFilter{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("a failed scan changed the catalog: %+v", entries)
	}
}

func TestSkippedTableKeepsItsClassifications(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	enrolled := platform.enroll(t, created.ID, environment.ID)
	sourceID := platform.addSource(t, enrolled, placeholderSource()).String()
	path := &agentv1.TablePath{Database: "crm", Schema: "public", Table: "users"}
	tables := []*agentv1.TableSnapshot{{
		Path: path, Kind: agentv1.TableKind_TABLE_KIND_TABLE,
		Columns: []*agentv1.ColumnSnapshot{{Name: "email", NativeType: "text", Ordinal: 1}},
	}}
	submit := func(result *agentv1.ScanResult) {
		t.Helper()
		job, err := platform.app.Scans.Request(ctx, created.ID, mustUUID(t, sourceID), "tester")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := enrolled.client.PullJobs(ctx, 1); err != nil {
			t.Fatal(err)
		}
		result.JobId, result.SourceId, result.Tables = job.ID.String(), sourceID, tables
		if err := enrolled.client.SubmitScanResult(ctx, result); err != nil {
			t.Fatalf("submit: %v", err)
		}
	}
	listed := func() int {
		t.Helper()
		_, total, err := platform.store.ListCatalog(ctx, created.ID, asset.CatalogFilter{Limit: 10})
		if err != nil {
			t.Fatal(err)
		}
		return int(total)
	}

	submit(&agentv1.ScanResult{
		Outcome: agentv1.ScanOutcome_SCAN_OUTCOME_COMPLETED,
		Classifications: []*agentv1.ColumnClassification{{
			Column: &agentv1.ColumnPath{Table: path, Column: "email"}, CategoryId: classifier.CategoryEmail, Confidence: 0.9,
			Evidence: &agentv1.ClassificationEvidence{}, Profile: &agentv1.ColumnProfile{},
		}},
	})
	submit(&agentv1.ScanResult{
		Outcome:       agentv1.ScanOutcome_SCAN_OUTCOME_PARTIAL,
		SkippedTables: []*agentv1.SkippedTable{{Table: path, ReasonCode: "READ_FAILED"}},
	})
	if listed() != 1 {
		t.Fatal("a table that was not read lost its classification")
	}
	submit(&agentv1.ScanResult{Outcome: agentv1.ScanOutcome_SCAN_OUTCOME_COMPLETED})
	if listed() != 0 {
		t.Fatal("a table read in full must lose a classification no longer found")
	}
}
