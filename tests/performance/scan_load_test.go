//go:build performance

// Package performance measures what a scan costs the database it scans. The test
// fails on budget violations; latency numbers are reported, not asserted, because
// they depend on the machine.
package performance_test

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"dataguard/internal/agent/scanner"
	"dataguard/internal/classifier"
	"dataguard/internal/connector"
	"dataguard/internal/connector/postgres"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/safelog"
	"dataguard/internal/testkit/stand"
)

const (
	tableRows   = 300_000
	probeCount  = 2_000
	rowsPerScan = 20_000
	rowsPerSec  = 10_000
)

func latencies(t *testing.T, ctx context.Context, source stand.Source, count int) []time.Duration {
	t.Helper()
	result := make([]time.Duration, 0, count)
	for i := range count {
		started := time.Now()
		var email string
		if err := source.Admin.QueryRowContext(ctx, `SELECT email FROM dg_load WHERE id = $1`, i%tableRows+1).Scan(&email); err != nil {
			t.Fatal(err)
		}
		result = append(result, time.Since(started))
	}
	slices.Sort(result)
	return result
}

func percentile(values []time.Duration, share float64) time.Duration {
	return values[int(float64(len(values)-1)*share)]
}

func TestScanStaysWithinBudgetAndBarelyTouchesLatency(t *testing.T) {
	ctx := t.Context()
	source := stand.PostgresSource(t)
	for _, statement := range []string{
		`DROP TABLE IF EXISTS dg_load`,
		`CREATE TABLE dg_load (id bigint PRIMARY KEY, email text, note text)`,
		fmt.Sprintf(`INSERT INTO dg_load SELECT g, 'dgcanary.' || g || '@example.invalid', repeat('x', 200) FROM generate_series(1, %d) g`, tableRows),
		`ANALYZE dg_load`,
	} {
		if _, err := source.Admin.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	password := source.Config.Password
	target, err := postgres.Open(connector.Credentials{
		Host: source.Config.Host, Port: source.Config.Port, Database: source.Config.Database,
		Username: source.Config.Username, Password: password, TLS: connector.TLSDisable,
	}, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = target.Close() }()

	baseline := latencies(t, ctx, source, probeCount)

	var result *agentv1.ScanResult
	var running sync.WaitGroup
	started := time.Now()
	running.Go(func() {
		job := &agentv1.ScanJob{JobId: "0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e1f", Budget: &agentv1.ScanBudget{
			MaxRowsPerTable: rowsPerScan, MaxRowsPerSecond: rowsPerSec, MaxConnections: 2,
		}}
		result = scanner.New(classifier.NewEngine(classifier.Custom{}), safelog.Discard()).Scan(ctx, target, job)
	})
	during := latencies(t, ctx, source, probeCount)
	running.Wait()
	elapsed := time.Since(started)

	for _, item := range result.GetClassifications() {
		if item.GetColumn().GetTable().GetTable() != "dg_load" {
			continue
		}
		inspected := item.GetProfile().GetRowsInspected()
		if inspected > rowsPerScan {
			t.Fatalf("read %d rows with a budget of %d", inspected, rowsPerScan)
		}
		if item.GetProfile().GetSamplingMethod() != agentv1.SamplingMethod_SAMPLING_METHOD_ENGINE_SAMPLE {
			t.Fatalf("a table larger than the budget must be sampled, got %s", item.GetProfile().GetSamplingMethod())
		}
	}
	// The limiter is the only thing slowing a scan this small, so it must show.
	minimum := time.Duration(float64(rowsPerScan)/rowsPerSec*float64(time.Second)) * 8 / 10
	if elapsed < minimum {
		t.Fatalf("scan took %s, the rate limit allows no less than %s", elapsed, minimum)
	}
	t.Logf("scan: %s, outcome %s", elapsed.Round(time.Millisecond), result.GetOutcome())
	t.Logf("point query p50 %s → %s, p95 %s → %s, p99 %s → %s",
		percentile(baseline, 0.5), percentile(during, 0.5),
		percentile(baseline, 0.95), percentile(during, 0.95),
		percentile(baseline, 0.99), percentile(during, 0.99))
	if _, err := source.Admin.ExecContext(ctx, `DROP TABLE dg_load`); err != nil {
		t.Fatal(err)
	}
}
