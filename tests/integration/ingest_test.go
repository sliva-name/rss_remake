//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"connectrpc.com/connect"
	chdriver "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"dataguard/internal/classifier"
	"dataguard/internal/core/audit"
	"dataguard/internal/core/scan"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/gen/restapi"
	"dataguard/internal/server/api"
	"dataguard/internal/server/storage/clickhouse"
	"dataguard/internal/testkit/seed"
	"dataguard/internal/testkit/stand"
	"dataguard/internal/testkit/synthetic"
	"dataguard/migrations"
)

func searchWindow() audit.Filter {
	return audit.Filter{From: time.Now().Add(-time.Hour), To: time.Now().Add(time.Hour), Limit: 500}
}

func (p *platform) search(t *testing.T, tenantID uuid.UUID, filter audit.Filter) ([]audit.Event, uint64) {
	t.Helper()
	events, total, err := p.events.Search(context.Background(), tenantID, filter)
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	return events, total
}

// scanAndAudit brings up a real agent that has classified the source.
func scanAndAudit(t *testing.T, source stand.Source) (*platform, uuid.UUID, uuid.UUID, *runningAgent) {
	t.Helper()
	ctx := context.Background()
	if err := seed.Tables(ctx, source.Admin, source.Dialect, 40, synthetic.New(21)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	source.Config.AuditDirectory = stand.AuditDirectory(source.Dialect.Name)
	agent, ids := platform.startAgent(t, platform.enroll(t, created.ID, environment.ID), source.Config)
	sourceID := ids[0]
	job, err := platform.app.Scans.Request(ctx, created.ID, sourceID, "tester")
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if finished := waitForScan(t, platform, created.ID, job.ID); finished.Status != scan.StatusCompleted {
		t.Fatalf("scan: %+v", finished)
	}
	agent.awaitObserving(t)
	return platform, created.ID, sourceID, agent
}

// awaitObserving waits for the collector to find the end of the log. Reading starts
// there, so anything earlier is history the agent is not meant to see.
func (a *runningAgent) awaitObserving(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(auditWait)
	for time.Now().Before(deadline) {
		_, reports := a.audit.Health()
		if len(reports) == 1 && reports[0].GetState() == agentv1.AuditSourceState_AUDIT_SOURCE_STATE_OBSERVING {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("collector never observed the source")
}

func awaitEvents(t *testing.T, platform *platform, tenantID uuid.UUID, want uint64, filter audit.Filter) []audit.Event {
	t.Helper()
	deadline := time.Now().Add(auditWait)
	for {
		events, total := platform.search(t, tenantID, filter)
		if total >= want {
			return events
		}
		if time.Now().After(deadline) {
			t.Fatalf("stored %d events, want %d", total, want)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestAuditReachesAnalyticsWithClassification(t *testing.T) {
	ctx := context.Background()
	source := stand.PostgresSource(t)
	platform, tenantID, sourceID, _ := scanAndAudit(t, source)
	platform.authn["analyst"] = api.Principal{Subject: "a", TenantID: tenantID, Roles: []string{api.RoleSecurityAnalyst}}

	statement := fmt.Sprintf(`SELECT email, inn FROM %s WHERE email = '%s.lit@example.invalid'`, seed.Users, synthetic.CanaryMarker)
	if _, err := source.Admin.ExecContext(ctx, statement); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Admin.ExecContext(ctx, `SELECT note FROM `+seed.Orders); err != nil {
		t.Fatal(err)
	}

	filter := searchWindow()
	filter.Category = classifier.CategoryEmail
	filter.Principal = "dg_app"
	events := awaitEvents(t, platform, tenantID, 1, filter)
	event := events[0]
	if event.SourceID != sourceID || event.Type != "EVENT_TYPE_DATA_ACCESS" {
		t.Fatalf("event = %+v", event)
	}
	if !strings.Contains(strings.Join(event.Categories, ","), classifier.CategoryTaxID) {
		t.Fatalf("categories = %v", event.Categories)
	}
	if len(event.ColumnIDs) == 0 {
		t.Fatal("columns were not linked to the catalog")
	}

	status, payload := restCall(t, platform, http.MethodGet, "/api/v1/audit/events?category="+classifier.CategoryEmail+"&principal=dg_app", "analyst", "")
	if status != http.StatusOK || strings.Contains(string(payload), synthetic.CanaryMarker) {
		t.Fatalf("events api: %d %s", status, payload)
	}
	var page restapi.AuditEventPage
	if err := json.Unmarshal(payload, &page); err != nil || page.Total == 0 {
		t.Fatalf("page: %s, %v", payload, err)
	}

	status, payload = restCall(t, platform, http.MethodGet, "/api/v1/analytics/principals", "analyst", "")
	if status != http.StatusOK || !strings.Contains(string(payload), "dg_app") {
		t.Fatalf("principals: %d %s", status, payload)
	}
	status, payload = restCall(t, platform, http.MethodGet, "/api/v1/analytics/categories", "analyst", "")
	if status != http.StatusOK || !strings.Contains(string(payload), classifier.CategoryEmail) {
		t.Fatalf("categories: %d %s", status, payload)
	}
	status, payload = restCall(t, platform, http.MethodGet, "/api/v1/analytics/summary", "analyst", "")
	if status != http.StatusOK {
		t.Fatalf("summary: %d %s", status, payload)
	}
	var summary restapi.AccessSummary
	if err := json.Unmarshal(payload, &summary); err != nil || summary.SensitiveEvents == 0 || summary.Events < summary.SensitiveEvents {
		t.Fatalf("summary: %s, %v", payload, err)
	}
	assertCoverage(t, platform, sourceID)
}

func assertCoverage(t *testing.T, platform *platform, sourceID uuid.UUID) {
	t.Helper()
	deadline := time.Now().Add(auditWait)
	for {
		status, payload := restCall(t, platform, http.MethodGet, "/api/v1/audit/coverage", "analyst", "")
		if status != http.StatusOK {
			t.Fatalf("coverage: %d %s", status, payload)
		}
		var rows []restapi.CoverageRow
		if err := json.Unmarshal(payload, &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) == 1 && rows[0].SourceId == sourceID && rows[0].Status == restapi.OBSERVING && rows[0].ColumnsShare != nil {
			row := rows[0]
			if !row.ReadsAudited || row.Statements == 0 || row.LastScanStatus == nil || *row.LastScanStatus != scan.StatusCompleted {
				t.Fatalf("row = %+v", row)
			}
			if *row.ColumnsShare <= 0 || *row.PrincipalShare != 1 || *row.VerifiedShare != 0 {
				t.Fatalf("shares = %v %v %v", *row.ColumnsShare, *row.PrincipalShare, *row.VerifiedShare)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("coverage never settled: %s", payload)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestCenterOutageLosesNothingAndDuplicatesNothing(t *testing.T) {
	ctx := context.Background()
	source := stand.PostgresSource(t)
	platform, tenantID, _, agent := scanAndAudit(t, source)
	marker := func(i int) string { return fmt.Sprintf(`SELECT status, %d FROM %s`, i, seed.Users) }

	platform.gate.down.Store(true)
	const during = 12
	for i := range during {
		if _, err := source.Admin.ExecContext(ctx, marker(i)); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(auditWait)
	for {
		stats, err := agent.events.Stats()
		if err != nil {
			t.Fatal(err)
		}
		if stats.PendingEvents >= during-1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("queue did not fill during the outage: %+v", stats)
		}
		time.Sleep(50 * time.Millisecond)
	}
	before, _ := platform.search(t, tenantID, searchWindow())
	platform.gate.down.Store(false)
	if _, err := source.Admin.ExecContext(ctx, `SELECT 'done' FROM `+seed.Orders); err != nil {
		t.Fatal(err)
	}

	countStatus := func(events []audit.Event) int {
		count := 0
		for _, event := range events {
			if strings.Contains(strings.Join(event.Columns, ","), seed.Users+".status") {
				count++
			}
		}
		return count
	}
	deadline = time.Now().Add(auditWait)
	for {
		events, _ := platform.search(t, tenantID, searchWindow())
		if countStatus(events)-countStatus(before) >= during {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("delivered %d of %d after recovery", countStatus(events)-countStatus(before), during)
		}
		time.Sleep(100 * time.Millisecond)
	}
	events, total := platform.search(t, tenantID, searchWindow())
	identifiers := map[uuid.UUID]bool{}
	for _, event := range events {
		identifiers[event.ID] = true
	}
	if uint64(len(identifiers)) != total {
		t.Fatalf("%d unique of %d stored", len(identifiers), total)
	}

	// The outage and the recovery are visible to an operator without the center.
	samples := gather(t, agent.metrics.Gather)
	failed := 0.0
	for key, value := range samples {
		if strings.HasPrefix(key, "dataguard_agent_center_requests_total|code=unavailable|") {
			failed += value
		}
	}
	if failed == 0 {
		t.Errorf("calls during the outage were not counted as failed: %v", samples)
	}
	if samples["dataguard_agent_events_delivered_total"] < during {
		t.Errorf("delivered = %v, want at least %d", samples["dataguard_agent_events_delivered_total"], during)
	}
	if samples["dataguard_server_events_ingested_total|result=stored"] != 0 {
		t.Fatal("agent and server metrics must not share a registry")
	}
	if stored := gather(t, platform.metrics.Gather)["dataguard_server_events_ingested_total|result=stored"]; stored < during {
		t.Errorf("server stored = %v, want at least %d", stored, during)
	}
}

// awaitStored waits for the broker consumer to store exactly want events of the
// tenant, then checks that no more arrive: a duplicate would show up late.
func (p *platform) awaitStored(t *testing.T, tenantID uuid.UUID, want int) {
	t.Helper()
	deadline := time.Now().Add(auditWait)
	for {
		_, total := p.search(t, tenantID, searchWindow())
		if total == uint64(want) {
			break
		}
		if total > uint64(want) || time.Now().After(deadline) {
			t.Fatalf("stored %d events, want %d", total, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
	time.Sleep(500 * time.Millisecond)
	if _, total := p.search(t, tenantID, searchWindow()); total != uint64(want) {
		t.Fatalf("stored %d events after settling, want %d", total, want)
	}
}

func gather(t *testing.T, read func() (map[string]float64, error)) map[string]float64 {
	t.Helper()
	samples, err := read()
	if err != nil {
		t.Fatal(err)
	}
	return samples
}

func TestRedeliveryStoresOneRow(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	enrolled := platform.enroll(t, created.ID, environment.ID)
	sourceID := platform.addSource(t, enrolled, placeholderSource()).String()
	event := &agentv1.AuditEvent{
		EventId: uuid.NewString(), SourceId: sourceID,
		EventTime: timestamppb.Now(), EventType: agentv1.EventType_EVENT_TYPE_DATA_ACCESS,
	}
	for range 3 {
		accepted, err := enrolled.client.SubmitEvents(ctx, []*agentv1.AuditEvent{event})
		if err != nil || len(accepted) != 1 {
			t.Fatalf("SubmitEvents = %v, %v", accepted, err)
		}
	}
	platform.awaitStored(t, created.ID, 1)
	samples := gather(t, platform.metrics.Gather)
	if samples["dataguard_server_events_ingested_total|result=stored"] != 1 ||
		samples["dataguard_server_events_ingested_total|result=duplicate"] != 2 ||
		samples["dataguard_server_event_delivery_delay_seconds"] != 1 {
		t.Fatalf("ingest metrics = %v", samples)
	}
}

// An agent retries on timeout while the first attempt may still be writing, and
// the retry can reach another server instance. The check and the insert run
// under the agent's lock, so racing deliveries store each event once.
func TestConcurrentRedeliveryStoresEachEventOnce(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	enrolled := platform.enroll(t, created.ID, environment.ID)
	sourceID := platform.addSource(t, enrolled, placeholderSource()).String()
	batch := make([]*agentv1.AuditEvent, 50)
	for i := range batch {
		batch[i] = &agentv1.AuditEvent{
			EventId: uuid.NewString(), SourceId: sourceID,
			EventTime: timestamppb.Now(), EventType: agentv1.EventType_EVENT_TYPE_DATA_ACCESS,
		}
	}
	var group sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		group.Go(func() {
			if accepted, err := enrolled.client.SubmitEvents(ctx, batch); err != nil || len(accepted) != len(batch) {
				errs <- fmt.Errorf("SubmitEvents accepted %d: %w", len(accepted), err)
			}
		})
	}
	group.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	platform.awaitStored(t, created.ID, len(batch))
	events, total := platform.search(t, created.ID, searchWindow())
	identifiers := map[uuid.UUID]bool{}
	for _, event := range events {
		identifiers[event.ID] = true
	}
	if total != uint64(len(batch)) || len(identifiers) != len(batch) {
		t.Fatalf("stored %d rows, %d unique, want %d", total, len(identifiers), len(batch))
	}
}

// Reports read whole hours from the projection and the partial hours at the edges
// from the rows. Every way of cutting the window must count what the rows hold.
func TestReportsCountPartialAndWholeHoursExactly(t *testing.T) {
	ctx := context.Background()
	store, err := clickhouse.Open(ctx, stand.CenterEvents(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	tenantID, sourceID := uuid.New(), uuid.New()
	base := time.Now().UTC().Truncate(time.Hour).Add(-6 * time.Hour)
	var events []audit.Event
	for minute := 0; minute < 6*60; minute += 7 {
		event := audit.Event{
			ID: uuid.New(), TenantID: tenantID, AgentID: uuid.New(), SourceID: sourceID,
			Time: base.Add(time.Duration(minute) * time.Minute), Type: "EVENT_TYPE_DATA_ACCESS",
			DatabasePrincipal: fmt.Sprintf("user_%d", minute%3), IdentityConfidence: "IDENTITY_CONFIDENCE_DB_PRINCIPAL_ONLY",
			ExecutionStatus: "EXECUTION_STATUS_SUCCESS", ObjectResolution: "OBJECT_RESOLUTION_RESOLVED",
		}
		if minute%2 == 0 {
			event.Categories = []string{classifier.CategoryEmail}
		}
		events = append(events, event)
	}
	// Two inserts make two parts, so the projection is read across parts too.
	half := len(events) / 2
	for _, part := range [][]audit.Event{events[:half], events[half:]} {
		if err := store.Insert(ctx, part); err != nil {
			t.Fatal(err)
		}
	}
	for _, window := range []struct{ from, to time.Duration }{
		{20 * time.Minute, 3*time.Hour + 40*time.Minute},
		{time.Hour, 4 * time.Hour},
		{10 * time.Minute, 50 * time.Minute},
		{-time.Hour, 7 * time.Hour},
		{2 * time.Hour, 2 * time.Hour},
	} {
		from, to := base.Add(window.from), base.Add(window.to)
		var want, sensitive uint64
		for _, event := range events {
			if !event.Time.Before(from) && event.Time.Before(to) {
				want++
				if len(event.Categories) > 0 {
					sensitive++
				}
			}
		}
		summary, err := store.Summarize(ctx, tenantID, from, to)
		if err != nil {
			t.Fatal(err)
		}
		if summary.Events != want || summary.SensitiveEvents != sensitive {
			t.Errorf("window %v: summary %+v, want %d events, %d sensitive", window, summary, want, sensitive)
		}
		principals, err := store.ByPrincipal(ctx, tenantID, from, to)
		if err != nil {
			t.Fatal(err)
		}
		var byPrincipal uint64
		for _, row := range principals {
			byPrincipal += row.Events
		}
		categories, err := store.ByCategory(ctx, tenantID, from, to)
		if err != nil {
			t.Fatal(err)
		}
		var byCategory uint64
		for _, row := range categories {
			byCategory += row.Events
		}
		windows, err := store.Windows(ctx, tenantID, from, to)
		if err != nil {
			t.Fatal(err)
		}
		var statements uint64
		for _, row := range windows {
			statements += row.Statements
		}
		if byPrincipal != want || byCategory != sensitive || statements != want {
			t.Errorf("window %v: principals %d, categories %d, coverage %d, want %d and %d", window, byPrincipal, byCategory, statements, want, sensitive)
		}
	}
}

// The rewrite of ADR-0007 runs on live data once: replays folded by the old
// engine must become single rows, and the row policy must keep guarding the table.
func TestEventTableMigrationKeepsEventsOnceAndStaysIsolated(t *testing.T) {
	ctx := context.Background()
	owner, runtime := stand.EmptyCenterEvents(t)
	original, err := fs.ReadFile(migrations.ClickHouse, "clickhouse/0001_audit_events.sql")
	if err != nil {
		t.Fatal(err)
	}
	before := fstest.MapFS{"clickhouse/0001_audit_events.sql": {Data: original}}
	if err := clickhouse.Migrate(ctx, owner, runtime.Username, before, "clickhouse"); err != nil {
		t.Fatal(err)
	}
	store, err := clickhouse.Open(ctx, runtime)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	tenantID := uuid.New()
	events := make([]audit.Event, 3)
	for i := range events {
		events[i] = audit.Event{
			ID: uuid.New(), TenantID: tenantID, SourceID: uuid.New(), Type: "EVENT_TYPE_DATA_ACCESS",
			Time: time.Now().UTC().Truncate(time.Microsecond).Add(-time.Duration(i) * time.Minute),
		}
	}
	for _, batch := range [][]audit.Event{events, events[:1]} {
		if err := store.Insert(ctx, batch); err != nil {
			t.Fatal(err)
		}
	}
	if err := clickhouse.Migrate(ctx, owner, runtime.Username, migrations.ClickHouse, "clickhouse"); err != nil {
		t.Fatal(err)
	}
	if _, total, err := store.Search(ctx, tenantID, searchWindow()); err != nil || total != uint64(len(events)) {
		t.Fatalf("stored %d rows after migration, want %d: %v", total, len(events), err)
	}
	connection, err := chdriver.Open(&chdriver.Options{
		Addr: []string{runtime.Address},
		Auth: chdriver.Auth{Database: runtime.Database, Username: runtime.Username, Password: runtime.Password},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	var total uint64
	if err := connection.QueryRow(ctx, `SELECT count() FROM audit_events`).Scan(&total); err == nil {
		t.Fatalf("a query without the tenant setting must fail after migration, returned %d", total)
	}
}

// The reason for the broker (ADR-0009): while ClickHouse cannot be written, agents
// are still acknowledged, so their queues do not grow; the backlog waits in the
// broker and is stored once when ClickHouse returns.
func TestStorageOutageIsAbsorbedByTheBroker(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	enrolled := platform.enroll(t, created.ID, environment.ID)
	sourceID := platform.addSource(t, enrolled, placeholderSource()).String()

	platform.storeDown.Store(true)
	const batches, perBatch = 5, 40
	for range batches {
		batch := make([]*agentv1.AuditEvent, perBatch)
		for i := range batch {
			batch[i] = &agentv1.AuditEvent{
				EventId: uuid.NewString(), SourceId: sourceID,
				EventTime: timestamppb.Now(), EventType: agentv1.EventType_EVENT_TYPE_DATA_ACCESS,
			}
		}
		// Sent twice, as an agent does when an acknowledgement is lost.
		for range 2 {
			if accepted, err := enrolled.client.SubmitEvents(ctx, batch); err != nil || len(accepted) != perBatch {
				t.Fatalf("ingest must accept while storage is down: %d, %v", len(accepted), err)
			}
		}
	}
	deadline := time.Now().Add(auditWait)
	for {
		samples := gather(t, platform.metrics.Gather)
		if samples["dataguard_server_consumer_restarts_total"] > 0 && samples["dataguard_server_consumer_lag_records"] >= 2*batches*perBatch {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the outage is not visible: restarts %v, lag %v",
				samples["dataguard_server_consumer_restarts_total"], samples["dataguard_server_consumer_lag_records"])
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, total := platform.search(t, created.ID, searchWindow()); total != 0 {
		t.Fatalf("stored %d events while storage was down", total)
	}

	platform.storeDown.Store(false)
	platform.awaitStored(t, created.ID, batches*perBatch)
	samples := gather(t, platform.metrics.Gather)
	if samples["dataguard_server_events_ingested_total|result=duplicate"] != batches*perBatch {
		t.Fatalf("duplicates = %v, want %d", samples["dataguard_server_events_ingested_total|result=duplicate"], batches*perBatch)
	}
	deadline = time.Now().Add(auditWait)
	for gather(t, platform.metrics.Gather)["dataguard_server_consumer_lag_records"] != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the consumer did not catch up")
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func TestAgentCannotReportOnAnotherAgentsSource(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	owner := platform.enroll(t, created.ID, environment.ID)
	intruder := platform.enroll(t, created.ID, environment.ID)
	sourceID := platform.addSource(t, owner, placeholderSource()).String()
	_, err := intruder.client.SubmitEvents(ctx, []*agentv1.AuditEvent{{
		EventId: uuid.NewString(), SourceId: sourceID, EventTime: timestamppb.Now(),
	}})
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("err = %v", err)
	}
	if _, total := platform.search(t, created.ID, searchWindow()); total != 0 {
		t.Fatalf("stored %d forged events", total)
	}
}

// TestRowPolicyHoldsWithoutTheApplicationFilter talks to ClickHouse as the runtime
// user. If it passes, a query that forgets WHERE tenant_id still cannot cross
// tenants.
func TestRowPolicyHoldsWithoutTheApplicationFilter(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	first, firstEnvironment := platform.newTenant(t, "Acme")
	second, secondEnvironment := platform.newTenant(t, "Globex")
	for _, tenantCase := range []struct {
		id          uuid.UUID
		environment uuid.UUID
	}{{first.ID, firstEnvironment.ID}, {second.ID, secondEnvironment.ID}} {
		agent := platform.enroll(t, tenantCase.id, tenantCase.environment)
		sourceID := platform.addSource(t, agent, placeholderSource()).String()
		if _, err := agent.client.SubmitEvents(ctx, []*agentv1.AuditEvent{{
			EventId: uuid.NewString(), SourceId: sourceID, EventTime: timestamppb.Now(),
		}}); err != nil {
			t.Fatal(err)
		}
	}
	settings := platform.eventSettings
	connection, err := chdriver.Open(&chdriver.Options{
		Addr: []string{settings.Address},
		Auth: chdriver.Auth{Database: settings.Database, Username: settings.Username, Password: settings.Password},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()

	count := func(ctx context.Context) (uint64, error) {
		var total uint64
		err := connection.QueryRow(ctx, `SELECT count() FROM audit_events`).Scan(&total)
		return total, err
	}
	scoped := chdriver.Context(ctx, chdriver.WithSettings(chdriver.Settings{"SQL_tenant_id": chdriver.CustomSetting{Value: first.ID.String()}}))
	platform.awaitStored(t, first.ID, 1)
	platform.awaitStored(t, second.ID, 1)
	if total, err := count(scoped); err != nil || total != 1 {
		t.Fatalf("scoped count = %d, %v", total, err)
	}
	if total, err := count(ctx); err == nil {
		t.Fatalf("a query without the tenant setting must fail, returned %d", total)
	}
}

func TestTenantsSeeOnlyTheirOwnAnalytics(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	first, environment := platform.newTenant(t, "Acme")
	second, _ := platform.newTenant(t, "Globex")
	agent := platform.enroll(t, first.ID, environment.ID)
	sourceID := platform.addSource(t, agent, placeholderSource()).String()
	if _, err := agent.client.SubmitEvents(ctx, []*agentv1.AuditEvent{{
		EventId: uuid.NewString(), SourceId: sourceID, EventTime: timestamppb.Now(),
		EventType: agentv1.EventType_EVENT_TYPE_DATA_ACCESS,
		Actor:     &agentv1.Actor{DatabasePrincipal: "acme_only"},
	}}); err != nil {
		t.Fatal(err)
	}
	// The event must be stored first, or the check below would pass on an empty table.
	platform.awaitStored(t, first.ID, 1)
	platform.authn["other"] = api.Principal{Subject: "o", TenantID: second.ID, Roles: []string{api.RoleAuditor}}
	for _, path := range []string{"/api/v1/audit/events", "/api/v1/analytics/principals", "/api/v1/audit/coverage"} {
		status, payload := restCall(t, platform, http.MethodGet, path, "other", "")
		if status != http.StatusOK || strings.Contains(string(payload), "acme_only") || strings.Contains(string(payload), "crm") {
			t.Fatalf("%s: %d %s", path, status, payload)
		}
	}
}
