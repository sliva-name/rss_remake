package coverage_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"dataguard/internal/core/audit"
	"dataguard/internal/core/coverage"
	"dataguard/internal/core/fleet"
)

type fakeFleet struct {
	fleet.Repository
	sources []fleet.Source
}

func (f fakeFleet) ListSources(context.Context, uuid.UUID) ([]fleet.Source, error) {
	return f.sources, nil
}

type fakeStore struct {
	health []coverage.Health
	scans  map[uuid.UUID]coverage.ScanState
}

func (f fakeStore) HealthReports(context.Context, uuid.UUID) ([]coverage.Health, error) {
	return f.health, nil
}

func (f fakeStore) LatestScans(context.Context, uuid.UUID) (map[uuid.UUID]coverage.ScanState, error) {
	return f.scans, nil
}

type fakeEvents struct {
	audit.Reader
	windows []audit.SourceWindow
}

func (f fakeEvents) Windows(context.Context, uuid.UUID, time.Time, time.Time) ([]audit.SourceWindow, error) {
	return f.windows, nil
}

func report(t *testing.T, source fleet.Source, health []coverage.Health, windows []audit.SourceWindow) coverage.Row {
	t.Helper()
	service := coverage.NewService(
		fleet.NewService(fakeFleet{sources: []fleet.Source{source}}, nil),
		fakeStore{health: health}, fakeEvents{windows: windows})
	rows, err := service.Report(context.Background(), uuid.New(), time.Hour)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %+v, %v", rows, err)
	}
	return rows[0]
}

func healthy(id uuid.UUID) coverage.Health {
	return coverage.Health{SourceID: id, State: "AUDIT_SOURCE_STATE_OBSERVING", ReportedAt: time.Now()}
}

func TestSourceWithoutReportsIsBlind(t *testing.T) {
	row := report(t, fleet.Source{ID: uuid.New()}, nil, nil)
	if row.Status != coverage.StatusBlind {
		t.Fatalf("row = %+v", row)
	}
}

func TestStaleReportIsBlindEvenIfItSaidObserving(t *testing.T) {
	id := uuid.New()
	health := healthy(id)
	health.ReportedAt = time.Now().Add(-time.Hour)
	row := report(t, fleet.Source{ID: id}, []coverage.Health{health}, nil)
	if row.Status != coverage.StatusBlind || row.Reason != "AGENT_SILENT" {
		t.Fatalf("row = %+v", row)
	}
}

func TestQuietObservedSourceHasEmptySharesNotZero(t *testing.T) {
	id := uuid.New()
	row := report(t, fleet.Source{ID: id}, []coverage.Health{healthy(id)}, nil)
	if row.Status != coverage.StatusObserving {
		t.Fatalf("row = %+v", row)
	}
	if row.ColumnsShare != nil || row.VerifiedShare != nil {
		t.Fatal("no statements means no measurement")
	}
}

func TestSharesAreMeasured(t *testing.T) {
	id := uuid.New()
	row := report(t, fleet.Source{ID: id}, []coverage.Health{healthy(id)}, []audit.SourceWindow{{
		SourceID: id, Statements: 4, Resolved: 3, Verified: 1, Identified: 2, Gaps: 1,
	}})
	if *row.ColumnsShare != 0.75 || *row.VerifiedShare != 0.25 || *row.PrincipalShare != 0.5 || row.Gaps != 1 {
		t.Fatalf("row = %+v", row)
	}
}

func TestReadAuditComesFromCapabilityOnly(t *testing.T) {
	id := uuid.New()
	writeOnly := fleet.Source{ID: id, Capabilities: []fleet.Capability{
		{Capability: "CAPABILITY_NATIVE_AUDIT", Support: "SUPPORT_AVAILABLE"},
		{Capability: "CAPABILITY_READ_AUDIT", Support: "SUPPORT_NOT_CONFIGURED"},
	}}
	if report(t, writeOnly, []coverage.Health{healthy(id)}, nil).ReadsAudited {
		t.Fatal("native audit alone does not mean reads are audited")
	}
}

func TestStatesMap(t *testing.T) {
	id := uuid.New()
	cases := map[string]string{
		"AUDIT_SOURCE_STATE_DEGRADED":       coverage.StatusDegraded,
		"AUDIT_SOURCE_STATE_UNAVAILABLE":    coverage.StatusBlind,
		"AUDIT_SOURCE_STATE_NOT_CONFIGURED": coverage.StatusNotConfigured,
	}
	for state, want := range cases {
		health := healthy(id)
		health.State, health.ReasonCode = state, "SOME_REASON"
		row := report(t, fleet.Source{ID: id}, []coverage.Health{health}, nil)
		if row.Status != want || row.Reason != "SOME_REASON" {
			t.Errorf("%s: row = %+v", state, row)
		}
	}
}
