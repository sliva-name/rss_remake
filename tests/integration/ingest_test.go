//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	chdriver "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"dataguard/internal/agent/config"
	"dataguard/internal/classifier"
	"dataguard/internal/core/audit"
	"dataguard/internal/core/scan"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/gen/restapi"
	"dataguard/internal/server/api"
	"dataguard/internal/testkit/seed"
	"dataguard/internal/testkit/stand"
	"dataguard/internal/testkit/synthetic"
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
	source.Config.Audit.Directory = stand.AuditDirectory(source.Dialect.Name)
	agent := platform.startAgent(t, platform.enroll(t, created.ID, environment.ID), []config.Source{source.Config})
	sourceID := waitForSource(t, platform, created.ID, source.Config.Key)
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
}

func TestRedeliveryStoresOneRow(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	enrolled := platform.enroll(t, created.ID, environment.ID)
	assigned, err := enrolled.client.ReportSources(ctx, []*agentv1.SourceReport{{SourceKey: "crm", Engine: agentv1.Engine_ENGINE_POSTGRESQL}})
	if err != nil {
		t.Fatal(err)
	}
	event := &agentv1.AuditEvent{
		EventId: uuid.NewString(), SourceId: assigned.GetAssignments()[0].GetSourceId(),
		EventTime: timestamppb.Now(), EventType: agentv1.EventType_EVENT_TYPE_DATA_ACCESS,
	}
	for range 3 {
		accepted, err := enrolled.client.SubmitEvents(ctx, []*agentv1.AuditEvent{event})
		if err != nil || len(accepted) != 1 {
			t.Fatalf("SubmitEvents = %v, %v", accepted, err)
		}
	}
	if _, total := platform.search(t, created.ID, searchWindow()); total != 1 {
		t.Fatalf("stored %d rows", total)
	}
}

func TestAgentCannotReportOnAnotherAgentsSource(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	owner := platform.enroll(t, created.ID, environment.ID)
	intruder := platform.enroll(t, created.ID, environment.ID)
	assigned, err := owner.client.ReportSources(ctx, []*agentv1.SourceReport{{SourceKey: "crm", Engine: agentv1.Engine_ENGINE_POSTGRESQL}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = intruder.client.SubmitEvents(ctx, []*agentv1.AuditEvent{{
		EventId: uuid.NewString(), SourceId: assigned.GetAssignments()[0].GetSourceId(), EventTime: timestamppb.Now(),
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
		assigned, err := agent.client.ReportSources(ctx, []*agentv1.SourceReport{{SourceKey: "crm", Engine: agentv1.Engine_ENGINE_POSTGRESQL}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := agent.client.SubmitEvents(ctx, []*agentv1.AuditEvent{{
			EventId: uuid.NewString(), SourceId: assigned.GetAssignments()[0].GetSourceId(), EventTime: timestamppb.Now(),
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
	assigned, err := agent.client.ReportSources(ctx, []*agentv1.SourceReport{{SourceKey: "crm", Engine: agentv1.Engine_ENGINE_POSTGRESQL}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.client.SubmitEvents(ctx, []*agentv1.AuditEvent{{
		EventId: uuid.NewString(), SourceId: assigned.GetAssignments()[0].GetSourceId(), EventTime: timestamppb.Now(),
		EventType: agentv1.EventType_EVENT_TYPE_DATA_ACCESS,
		Actor:     &agentv1.Actor{DatabasePrincipal: "acme_only"},
	}}); err != nil {
		t.Fatal(err)
	}
	platform.authn["other"] = api.Principal{Subject: "o", TenantID: second.ID, Roles: []string{api.RoleAuditor}}
	for _, path := range []string{"/api/v1/audit/events", "/api/v1/analytics/principals", "/api/v1/audit/coverage"} {
		status, payload := restCall(t, platform, http.MethodGet, path, "other", "")
		if status != http.StatusOK || strings.Contains(string(payload), "acme_only") || strings.Contains(string(payload), "crm") {
			t.Fatalf("%s: %d %s", path, status, payload)
		}
	}
}
