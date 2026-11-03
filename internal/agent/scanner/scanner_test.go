package scanner_test

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"dataguard/internal/agent/scanner"
	"dataguard/internal/classifier"
	"dataguard/internal/connector"
	"dataguard/internal/contract/egress"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/safeerr"
	"dataguard/internal/platform/safelog"
	"dataguard/internal/testkit/synthetic"
)

const (
	jobID    = "0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e1f"
	sourceID = "0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e20"
)

type fakeSource struct {
	tables     []connector.Table
	catalogErr error
	sampleErr  map[string]error
	rows       int
	truncate   bool
	limitsMu   sync.Mutex
	lastLimits connector.Limits
}

func (f *fakeSource) Close() error { return nil }

func (f *fakeSource) Probe(context.Context) (string, []*agentv1.CapabilityStatus) { return "1", nil }

func (f *fakeSource) Tables(context.Context) ([]connector.Table, error) {
	return f.tables, f.catalogErr
}

func (f *fakeSource) Sample(ctx context.Context, table connector.Table, columns []connector.Column, limits connector.Limits, visit connector.Visitor) (connector.SampleStats, error) {
	f.limitsMu.Lock()
	f.lastLimits = limits
	f.limitsMu.Unlock()
	if err := f.sampleErr[table.Name]; err != nil {
		return connector.SampleStats{}, err
	}
	generator := synthetic.New(1)
	for range f.rows {
		for i, column := range columns {
			switch column.Name {
			case "email":
				visit(i, []byte(generator.Email()))
			case "status":
				visit(i, []byte("active"))
			}
		}
		if err := ctx.Err(); err != nil {
			return connector.SampleStats{}, err
		}
	}
	return connector.SampleStats{
		Rows: uint64(f.rows), Method: agentv1.SamplingMethod_SAMPLING_METHOD_ENGINE_SAMPLE, Truncated: f.truncate,
	}, nil
}

func table(name string) connector.Table {
	return connector.Table{
		Database: "crm", Schema: "public", Name: name, Kind: agentv1.TableKind_TABLE_KIND_TABLE,
		Columns: []connector.Column{
			{Name: "email", NativeType: "text", Comment: "Контакт " + synthetic.CanaryMarker},
			{Name: "status", NativeType: "text"},
			{Name: "password_hash", NativeType: "bytea"},
		},
	}
}

func run(source *fakeSource, budget *agentv1.ScanBudget) *agentv1.ScanResult {
	engine := classifier.NewEngine(classifier.Custom{})
	job := &agentv1.ScanJob{JobId: jobID, SourceId: sourceID, Budget: budget}
	return scanner.New(engine, safelog.Discard()).Scan(context.Background(), source, job)
}

func categories(result *agentv1.ScanResult) map[string]string {
	found := map[string]string{}
	for _, item := range result.GetClassifications() {
		found[item.GetColumn().GetColumn()] = item.GetCategoryId()
	}
	return found
}

func TestScanClassifiesAndReportsAggregates(t *testing.T) {
	result := run(&fakeSource{tables: []connector.Table{table("users")}, rows: 100}, nil)

	if result.GetOutcome() != agentv1.ScanOutcome_SCAN_OUTCOME_COMPLETED {
		t.Fatalf("outcome = %s", result.GetOutcome())
	}
	found := categories(result)
	if found["email"] != classifier.CategoryEmail || found["password_hash"] != classifier.CategoryPassword {
		t.Fatalf("categories = %v", found)
	}
	if _, classified := found["status"]; classified {
		t.Fatal("status must stay unclassified")
	}
	for _, item := range result.GetClassifications() {
		if item.GetColumn().GetColumn() != "email" {
			continue
		}
		profile := item.GetProfile()
		if profile.GetRowsInspected() != 100 || profile.GetRowsMatched() != 100 || profile.GetUniqueEstimate() == 0 {
			t.Fatalf("profile = %+v", profile)
		}
	}
}

func TestScanResultPassesEgressAndCarriesNoValues(t *testing.T) {
	result := run(&fakeSource{tables: []connector.Table{table("users")}, rows: 50}, nil)

	if err := egress.Check(result); err != nil {
		t.Fatalf("egress: %v", err)
	}
	wire, err := proto.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(wire, []byte(synthetic.CanaryMarker)) {
		t.Fatal("scan result carries a synthetic value or a column comment")
	}
}

func TestCatalogFailureIsReportedAsFailure(t *testing.T) {
	cause := safeerr.New("read catalog", safeerr.CodeQuery, errors.New("connection refused"))
	result := run(&fakeSource{catalogErr: cause}, nil)

	if result.GetOutcome() != agentv1.ScanOutcome_SCAN_OUTCOME_FAILED || result.GetFailureCode() != "QUERY_FAILED" {
		t.Fatalf("result = %+v", result)
	}
}

func TestUnreadableTableMakesScanPartial(t *testing.T) {
	source := &fakeSource{
		tables:    []connector.Table{table("users"), table("locked")},
		rows:      30,
		sampleErr: map[string]error{"locked": safeerr.New("run sample", safeerr.CodeQuery, errors.New("denied"))},
	}
	result := run(source, nil)

	if result.GetOutcome() != agentv1.ScanOutcome_SCAN_OUTCOME_PARTIAL {
		t.Fatalf("outcome = %s", result.GetOutcome())
	}
	skipped := result.GetSkippedTables()
	if len(skipped) != 1 || skipped[0].GetTable().GetTable() != "locked" || skipped[0].GetReasonCode() != "READ_FAILED" {
		t.Fatalf("skipped = %+v", skipped)
	}
}

func TestTruncatedReadIsNotReportedAsComplete(t *testing.T) {
	result := run(&fakeSource{tables: []connector.Table{table("users")}, rows: 30, truncate: true}, nil)

	if result.GetOutcome() != agentv1.ScanOutcome_SCAN_OUTCOME_PARTIAL ||
		result.GetSkippedTables()[0].GetReasonCode() != "BUDGET_EXHAUSTED" {
		t.Fatalf("result = %+v", result)
	}
}

func TestViewsAreClassifiedFromMetadataOnly(t *testing.T) {
	view := table("users_view")
	view.Kind = agentv1.TableKind_TABLE_KIND_VIEW
	result := run(&fakeSource{tables: []connector.Table{view}, rows: 100}, nil)

	for _, item := range result.GetClassifications() {
		if item.GetProfile().GetSamplingMethod() != agentv1.SamplingMethod_SAMPLING_METHOD_METADATA_ONLY {
			t.Fatalf("view was sampled: %+v", item)
		}
	}
}

func TestBudgetIsPassedToTheConnector(t *testing.T) {
	source := &fakeSource{tables: []connector.Table{table("users")}, rows: 1}
	run(source, &agentv1.ScanBudget{MaxRowsPerTable: 7, MaxBytesPerTable: 9, MaxRowsPerSecond: 11})

	if source.lastLimits.MaxRows != 7 || source.lastLimits.MaxBytes != 9 || source.lastLimits.Limiter.Burst() != 11 {
		t.Fatalf("limits = %+v", source.lastLimits)
	}
}

func TestEmptyBudgetIsNeverUnbounded(t *testing.T) {
	budget := scanner.EffectiveBudget(nil)
	if budget.GetMaxRowsPerTable() == 0 || budget.GetMaxBytesPerTable() == 0 || budget.GetMaxConnections() == 0 ||
		budget.GetMaxRowsPerSecond() == 0 || budget.GetMaxDurationSeconds() == 0 {
		t.Fatalf("budget = %+v", budget)
	}
}

func TestExpiredDeadlineSkipsRemainingTables(t *testing.T) {
	engine := classifier.NewEngine(classifier.Custom{})
	source := &fakeSource{tables: []connector.Table{table("users")}, rows: 1}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	job := &agentv1.ScanJob{JobId: jobID, SourceId: sourceID}

	result := scanner.New(engine, safelog.Discard()).Scan(ctx, source, job)

	if result.GetOutcome() != agentv1.ScanOutcome_SCAN_OUTCOME_PARTIAL {
		t.Fatalf("outcome = %s", result.GetOutcome())
	}
}
