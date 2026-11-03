package collector

import (
	"context"
	"testing"
	"time"
	_ "time/tzdata"

	"dataguard/internal/agent/queue"
	"dataguard/internal/connector"
	"dataguard/internal/contract/codes"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/safelog"
	"dataguard/internal/query/frontend/postgres"
)

func mustLocation(t *testing.T, name string) *time.Location {
	t.Helper()
	location, err := time.LoadLocation(name)
	if err != nil {
		t.Fatal(err)
	}
	return location
}

// jsonlog prints only the abbreviation of log_timezone; read in UTC, as in the
// agent's container, it used to come out with a zero offset.
func TestPostgresTimeUsesLogTimeZone(t *testing.T) {
	cases := []struct {
		zone, value string
		want        time.Time
	}{
		{"Europe/Moscow", "2026-11-03 12:00:00.000 MSK", time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)},
		{"Asia/Yekaterinburg", "2026-11-03 12:00:00.000 +05", time.Date(2026, 11, 3, 7, 0, 0, 0, time.UTC)},
		{"Europe/Berlin", "2026-07-01 12:00:00.000 CEST", time.Date(2026, 7, 1, 10, 0, 0, 0, time.UTC)},
		{"Europe/Berlin", "2026-12-01 12:00:00.000 CET", time.Date(2026, 12, 1, 11, 0, 0, 0, time.UTC)},
		{"Etc/UTC", "2026-11-03 12:00:00.000 UTC", time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		if got := parsePostgresTime(tc.value, mustLocation(t, tc.zone)); !got.Equal(tc.want) {
			t.Errorf("%s in %s = %s, want %s", tc.value, tc.zone, got, tc.want)
		}
	}
}

func TestMariaDBTimeUsesServerZone(t *testing.T) {
	parser := newMariaDBParser()
	parser.setLocation(time.FixedZone("", 3*60*60))
	records, ok := parser.feed([]byte(`20261103 12:00:00,host,dg_app,127.0.0.1,1,2,CONNECT,crm,,0`), fileCursor{})
	if !ok || len(records) != 1 {
		t.Fatalf("records = %+v, %v", records, ok)
	}
	if want := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC); !records[0].Time.Equal(want) {
		t.Fatalf("time = %s, want %s", records[0].Time, want)
	}
}

// With log_timestamps=SYSTEM every header ends in an offset instead of Z. Such
// lines used to match nothing and vanish as continuations of a statement.
func TestGeneralLogAcceptsSystemTimestamps(t *testing.T) {
	parser := newGeneralParser()
	lines := []string{
		"2026-11-03T12:00:00.000001+03:00\t  9 Connect\tdg_app@10.0.0.5 on crm using TCP/IP",
		"2026-11-03T12:00:01.000001+03:00\t  9 Query\tSELECT 1",
		"2026-11-03T12:00:02.000001+03:00\t  9 Quit\t",
	}
	var records []Record
	for i, line := range lines {
		got, ok := parser.feed([]byte(line), fileCursor{Offset: int64(i)})
		if !ok {
			t.Fatalf("line %d rejected", i)
		}
		records = append(records, got...)
	}
	if len(records) != 2 {
		t.Fatalf("records = %+v", records)
	}
	if want := time.Date(2026, 11, 3, 9, 0, 1, 1000, time.UTC); !records[1].Time.Equal(want) {
		t.Fatalf("time = %s, want %s", records[1].Time, want)
	}
}

type zonedScriptedReader struct {
	scriptedReader
	location *time.Location
}

func (r *zonedScriptedReader) setLocation(location *time.Location) { r.location = location }

type catalogWithoutClock struct{}

func (catalogWithoutClock) Tables(ctx context.Context) ([]connector.Table, error) {
	return staticCatalog{}.Tables(ctx)
}

func newZoneCollector(t *testing.T, reader Reader, catalog connector.Catalog) *Collector {
	t.Helper()
	events, err := queue.Open(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = events.Close() })
	return New(Options{
		SourceKey: "crm", SourceID: testSourceID, Reader: reader, Catalog: catalog,
		Frontend: postgres.Frontend{}, Schema: "public", Queue: events, Logger: safelog.Discard(),
	})
}

func TestZonedReaderWaitsForTheServerZone(t *testing.T) {
	blind := &zonedScriptedReader{scriptedReader: scriptedReader{batches: []Batch{{Records: []Record{statementRecord(1)}, Cursor: []byte("after")}}}}
	item := newZoneCollector(t, blind, catalogWithoutClock{})
	item.tick(context.Background())
	if health := item.Health(); health.GetState() != agentv1.AuditSourceState_AUDIT_SOURCE_STATE_DEGRADED ||
		health.GetReasonCode() != codes.LogTimeZoneUnknown {
		t.Fatalf("health = %+v", health)
	}
	if blind.position != 0 {
		t.Fatal("read before the time zone was known")
	}

	located := &zonedScriptedReader{}
	item = newZoneCollector(t, located, staticCatalog{})
	item.tick(context.Background())
	if located.location != time.UTC || item.Health().GetState() != agentv1.AuditSourceState_AUDIT_SOURCE_STATE_OBSERVING {
		t.Fatalf("location = %v, health = %+v", located.location, item.Health())
	}
}
