package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"dataguard/internal/agent/queue"
	"dataguard/internal/agent/telemetry"
	"dataguard/internal/connector"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/safelog"
	"dataguard/internal/query/frontend/postgres"
)

const (
	testSourceID = "0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e1f"
	canary       = "dgcanary.value@example.invalid"
)

func pgLine(t *testing.T, entry map[string]any) []byte {
	t.Helper()
	entry["backend_type"] = "client backend"
	if _, ok := entry["timestamp"]; !ok {
		entry["timestamp"] = "2026-11-03 01:39:29.296 UTC"
	}
	encoded, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func audit(statement string) string {
	return fmt.Sprintf(`AUDIT: SESSION,1,1,READ,SELECT,,,"%s",<not logged>`, strings.ReplaceAll(statement, `"`, `""`))
}

func feed(t *testing.T, parser *postgresParser, entry map[string]any, offset int64) []Record {
	t.Helper()
	records, ok := parser.feed(pgLine(t, entry), fileCursor{Inode: 1, Offset: offset})
	if !ok {
		t.Fatal("line rejected")
	}
	return records
}

func TestNextLineOfSessionProvesSuccess(t *testing.T) {
	parser := newPostgresParser()
	if got := feed(t, parser, map[string]any{"session_id": "s1", "vxid": "1/1", "message": audit("SELECT 1")}, 0); got != nil {
		t.Fatalf("a statement must wait for its outcome: %+v", got)
	}
	got := feed(t, parser, map[string]any{"session_id": "s1", "vxid": "1/2", "message": audit("SELECT 2")}, 10)
	if len(got) != 1 || got[0].Status != agentv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS {
		t.Fatalf("records = %+v", got)
	}
}

func TestErrorAfterAuditLineIsFailure(t *testing.T) {
	parser := newPostgresParser()
	feed(t, parser, map[string]any{"session_id": "s1", "vxid": "1/1", "message": audit("SELECT 1/0")}, 0)
	got := feed(t, parser, map[string]any{
		"session_id": "s1", "vxid": "1/1", "error_severity": "ERROR", "state_code": "22012",
		"message": "division by zero", "statement": "SELECT 1/0",
	}, 10)
	if len(got) != 1 || got[0].Status != agentv1.ExecutionStatus_EXECUTION_STATUS_FAILURE || got[0].ErrorCode != "22012" {
		t.Fatalf("records = %+v", got)
	}
}

func TestSessionsDoNotDecideForEachOther(t *testing.T) {
	parser := newPostgresParser()
	feed(t, parser, map[string]any{"session_id": "s1", "vxid": "1/1", "message": audit("SELECT 1")}, 0)
	if got := feed(t, parser, map[string]any{"session_id": "s2", "vxid": "2/1", "message": audit("SELECT 2")}, 10); got != nil {
		t.Fatalf("another session must not settle s1: %+v", got)
	}
}

func TestDisconnectProvesSuccess(t *testing.T) {
	parser := newPostgresParser()
	feed(t, parser, map[string]any{"session_id": "s1", "vxid": "1/1", "message": audit("SELECT 1")}, 0)
	got := feed(t, parser, map[string]any{"session_id": "s1", "message": "disconnection: session time: 0:00:01"}, 10)
	if len(got) != 1 || got[0].Status != agentv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS {
		t.Fatalf("records = %+v", got)
	}
}

func TestSilentSessionEndsAsUnknown(t *testing.T) {
	parser := newPostgresParser()
	clock := time.Now()
	parser.now = func() time.Time { return clock }
	feed(t, parser, map[string]any{"session_id": "s1", "vxid": "1/1", "message": audit("SELECT pg_sleep(100)")}, 0)
	if got := parser.flush(); got != nil {
		t.Fatalf("flushed too early: %+v", got)
	}
	clock = clock.Add(holdTimeout + time.Second)
	got := parser.flush()
	if len(got) != 1 || got[0].Status != agentv1.ExecutionStatus_EXECUTION_STATUS_UNKNOWN {
		t.Fatalf("records = %+v", got)
	}
}

func TestHeldRecordKeepsDurablePositionBehind(t *testing.T) {
	parser := newPostgresParser()
	feed(t, parser, map[string]any{"session_id": "s1", "vxid": "1/1", "message": audit("SELECT 1")}, 42)
	position, held := parser.oldestHeld()
	if !held || position.Offset != 42 {
		t.Fatalf("position = %+v, %v", position, held)
	}
}

func TestRejectedStatementIsTakenFromTheErrorLine(t *testing.T) {
	parser := newPostgresParser()
	got := feed(t, parser, map[string]any{
		"session_id": "s1", "vxid": "1/1", "error_severity": "ERROR", "state_code": "42501",
		"message": "permission denied", "statement": "SELECT secret FROM vault",
	}, 0)
	if len(got) != 1 || got[0].Status != agentv1.ExecutionStatus_EXECUTION_STATUS_FAILURE || got[0].Statement.IsEmpty() {
		t.Fatalf("records = %+v", got)
	}
}

func TestFailedLogin(t *testing.T) {
	parser := newPostgresParser()
	got := feed(t, parser, map[string]any{
		"session_id": "s1", "user": "attacker", "error_severity": "FATAL", "state_code": "28P01",
		"message": "password authentication failed",
	}, 0)
	if len(got) != 1 || got[0].Kind != KindLogin || got[0].Status != agentv1.ExecutionStatus_EXECUTION_STATUS_FAILURE {
		t.Fatalf("records = %+v", got)
	}
}

func TestContextIsBoundToItsTransaction(t *testing.T) {
	parser := newPostgresParser()
	setting := `AUDIT: SESSION,1,1,MISC,SET,,,"SET LOCAL dg.ctx = 'v1.abc.def'",<not logged>`
	feed(t, parser, map[string]any{"session_id": "s1", "vxid": "1/1", "message": setting}, 0)
	feed(t, parser, map[string]any{"session_id": "s1", "vxid": "1/1", "message": audit("SELECT 1")}, 10)
	first := feed(t, parser, map[string]any{"session_id": "s1", "vxid": "1/2", "message": audit("SELECT 2")}, 20)
	if len(first) != 1 || first[0].ContextToken != "v1.abc.def" {
		t.Fatalf("records = %+v", first)
	}
	second := feed(t, parser, map[string]any{"session_id": "s1", "message": "disconnection: x"}, 30)
	if len(second) != 1 || second[0].ContextToken != "" {
		t.Fatalf("the next transaction inherited a context: %+v", second)
	}
}

func TestOtherSettingsAreIgnored(t *testing.T) {
	parser := newPostgresParser()
	setting := `AUDIT: SESSION,1,1,MISC,SET,,,"SET LOCAL lock_timeout = 2000",<not logged>`
	if got := feed(t, parser, map[string]any{"session_id": "s1", "vxid": "1/1", "message": setting}, 0); got != nil {
		t.Fatalf("records = %+v", got)
	}
}

func TestBrokenLinesAreCountedNotFatal(t *testing.T) {
	parser := newPostgresParser()
	if _, ok := parser.feed([]byte("{not json"), fileCursor{}); ok {
		t.Fatal("broken line accepted")
	}
}

func TestStatementCannotBePrinted(t *testing.T) {
	statement := NewStatement("SELECT '" + canary + "'")
	record := Record{Statement: statement}
	for _, rendered := range []string{
		fmt.Sprint(statement), fmt.Sprintf("%v %+v %#v %s %q", statement, statement, statement, statement, statement),
		fmt.Sprintf("%v %+v", record, record),
	} {
		if strings.Contains(rendered, canary) {
			t.Fatalf("statement leaked: %s", rendered)
		}
	}
	if encoded, err := json.Marshal(statement); err != nil || strings.Contains(string(encoded), canary) {
		t.Fatalf("statement leaked through json: %s, %v", encoded, err)
	}
}

func TestGeneralLogJoinsMultilineStatements(t *testing.T) {
	parser := newGeneralParser()
	lines := []string{
		"2026-11-03T01:39:30.458373Z\t  536 Connect\tdg_app@10.0.0.5 on crm using SSL/TLS",
		"2026-11-03T01:39:30.458979Z\t  536 Query\tSELECT email",
		"FROM users",
		"WHERE id = 1",
		"2026-11-03T01:39:30.459705Z\t  536 Quit\t",
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
	statement := records[1]
	if statement.Statement.Reveal() != "SELECT email\nFROM users\nWHERE id = 1" {
		t.Fatalf("text = %q", statement.Statement.Reveal())
	}
	if statement.Principal != "dg_app" || statement.ClientAddress != "10.0.0.5" ||
		statement.Status != agentv1.ExecutionStatus_EXECUTION_STATUS_UNKNOWN {
		t.Fatalf("record = %+v", statement)
	}
}

func TestGeneralLogSessionsSurviveRestart(t *testing.T) {
	parser := newGeneralParser()
	parser.feed([]byte("2026-11-03T01:39:30.458373Z\t  7 Connect\tdg_app@10.0.0.5 on crm using TCP/IP"), fileCursor{})
	restored := newGeneralParser()
	restored.restore(parser.state())
	restored.feed([]byte("2026-11-03T01:39:31.000000Z\t  7 Query\tSELECT 1"), fileCursor{})
	if restored.current == nil || restored.current.record.Principal != "dg_app" {
		t.Fatalf("session lost: %+v", restored.current)
	}
}

func TestMariaDBLine(t *testing.T) {
	line := `20261103 01:39:30,host,dg_app,127.0.0.1,1478,5150,QUERY,crm,'SELECT a, b FROM t WHERE c=\'x,y\'',1146`
	records, ok := newMariaDBParser().feed([]byte(line), fileCursor{})
	if !ok || len(records) != 1 {
		t.Fatalf("records = %+v, %v", records, ok)
	}
	record := records[0]
	if record.Statement.Reveal() != `SELECT a, b FROM t WHERE c='x,y'` {
		t.Fatalf("text = %q", record.Statement.Reveal())
	}
	if record.Status != agentv1.ExecutionStatus_EXECUTION_STATUS_FAILURE || record.ErrorCode != "1146" {
		t.Fatalf("record = %+v", record)
	}
}

func writeLog(t *testing.T, path, content string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.WriteString(content); err != nil {
		t.Fatal(err)
	}
}

func collectLines(t *testing.T, reader *tail, position *fileCursor) ([]string, tailResult) {
	t.Helper()
	var lines []string
	result, _, err := reader.readFrom(position, func(line []byte, _ fileCursor) {
		lines = append(lines, string(line))
	})
	if err != nil {
		t.Fatal(err)
	}
	return lines, result
}

func TestTailWaitsForACompleteLine(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "a.log")
	writeLog(t, path, "one\ntwo")
	reader := &tail{pattern: filepath.Join(directory, "*.log"), maxRead: 1 << 20}
	lines, result := collectLines(t, reader, &fileCursor{Inode: inodeOf(t, path)})
	if len(lines) != 1 || lines[0] != "one" {
		t.Fatalf("lines = %v", lines)
	}
	writeLog(t, path, "three\n")
	lines, _ = collectLines(t, reader, &result.position)
	if len(lines) != 1 || lines[0] != "twothree" {
		t.Fatalf("lines = %v", lines)
	}
}

func inodeOf(t *testing.T, path string) uint64 {
	t.Helper()
	files, err := listFiles(path)
	if err != nil || len(files) != 1 {
		t.Fatalf("listFiles: %v, %v", files, err)
	}
	return files[0].inode
}

func TestTailFollowsARenamedFile(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.log")
	writeLog(t, path, "one\n")
	reader := &tail{pattern: path + "*", maxRead: 1 << 20}
	_, result := collectLines(t, reader, &fileCursor{Inode: inodeOf(t, path)})

	writeLog(t, path, "two\n")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	writeLog(t, path, "three\n")

	lines, after := collectLines(t, reader, &result.position)
	if strings.Join(lines, ",") != "two,three" || after.lost {
		t.Fatalf("lines = %v, lost = %v", lines, after.lost)
	}
}

func TestDeletedLogIsReportedAsLost(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.log")
	writeLog(t, path, "one\n")
	reader := &tail{pattern: path + "*", maxRead: 1 << 20}
	stale := &fileCursor{Inode: inodeOf(t, path) + 999, Offset: 4}
	lines, result := collectLines(t, reader, stale)
	if !result.lost || len(lines) != 1 {
		t.Fatalf("lines = %v, result = %+v", lines, result)
	}
}

func TestTruncatedLogIsReportedAsLost(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.log")
	writeLog(t, path, "short\n")
	reader := &tail{pattern: path + "*", maxRead: 1 << 20}
	_, result := collectLines(t, reader, &fileCursor{Inode: inodeOf(t, path), Offset: 1000})
	if !result.lost {
		t.Fatal("a shrunken file means lost records")
	}
}

func TestOversizedLineIsSkippedAndCounted(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.log")
	writeLog(t, path, strings.Repeat("x", maxLineBytes+10)+"\nnext\n")
	reader := &tail{pattern: path + "*", maxRead: 1 << 30}
	var lines []string
	_, skipped, err := reader.readFrom(&fileCursor{Inode: inodeOf(t, path)}, func(line []byte, _ fileCursor) {
		lines = append(lines, string(line))
	})
	if err != nil || skipped != 1 || len(lines) != 1 || lines[0] != "next" {
		t.Fatalf("lines = %d, skipped = %d, err = %v", len(lines), skipped, err)
	}
}

type staticCatalog struct{}

func (staticCatalog) LogLocation(context.Context) (*time.Location, error) { return time.UTC, nil }

func (staticCatalog) Tables(context.Context) ([]connector.Table, error) {
	return []connector.Table{{
		Database: "crm", Schema: "public", Name: "users", Kind: agentv1.TableKind_TABLE_KIND_TABLE,
		Columns: []connector.Column{{Name: "id"}, {Name: "email"}},
	}}, nil
}

type scriptedReader struct {
	batches  []Batch
	rewinds  int
	position int
}

func (r *scriptedReader) Read(context.Context, []byte) (Batch, error) {
	if r.position >= len(r.batches) {
		return Batch{Cursor: []byte("end")}, nil
	}
	batch := r.batches[r.position]
	r.position++
	return batch, nil
}

func (r *scriptedReader) Rewind() {
	r.rewinds++
	r.position = 0
}

func statementRecord(position int) Record {
	return Record{
		Position: fmt.Sprintf("%d", position), Time: time.Now(), Principal: "dg_app",
		Statement: NewStatement("SELECT email FROM users WHERE email = '" + canary + "'"),
		Status:    agentv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
	}
}

func newTestCollector(t *testing.T, reader Reader, capacity uint64) (*Collector, *queue.Queue) {
	t.Helper()
	events, err := queue.Open(t.TempDir(), capacity)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = events.Close() })
	return New(Options{
		SourceKey: "crm", SourceID: testSourceID, Reader: reader, Catalog: staticCatalog{},
		Frontend: postgres.Frontend{}, Schema: "public", Queue: events, Logger: safelog.Discard(),
	}), events
}

func TestFullQueueDoesNotLoseRecords(t *testing.T) {
	var records []Record
	for i := range 50 {
		records = append(records, statementRecord(i))
	}
	reader := &scriptedReader{batches: []Batch{{Records: records, Cursor: []byte("after")}}}
	item, events := newTestCollector(t, reader, 512)

	item.tick(context.Background())

	if reader.rewinds != 1 {
		t.Fatalf("rewinds = %d", reader.rewinds)
	}
	if cursor, err := events.Cursor("crm"); err != nil || cursor != nil {
		t.Fatalf("cursor moved past stored events: %q, %v", cursor, err)
	}
	health := item.Health()
	if health.GetState() != agentv1.AuditSourceState_AUDIT_SOURCE_STATE_DEGRADED || health.GetReasonCode() != reasonQueueFull {
		t.Fatalf("health = %+v", health)
	}
}

func TestLogLostWhileQueueWasFullIsBlamedOnTheQueue(t *testing.T) {
	var records []Record
	for i := range 50 {
		records = append(records, statementRecord(i))
	}
	reader := &scriptedReader{batches: []Batch{{Records: records, Cursor: []byte("after")}}}
	item, events := newTestCollector(t, reader, 512)
	item.tick(context.Background())

	reader.batches = []Batch{{Gap: lostLogGap(), Cursor: []byte("resumed")}}
	reader.position = 0
	item.tick(context.Background())

	items, err := events.Peek(10, 1<<20)
	if err != nil || len(items) != 1 {
		t.Fatalf("items = %d, %v", len(items), err)
	}
	gap := items[0].Event
	if gap.GetEventType() != agentv1.EventType_EVENT_TYPE_AUDIT_GAP ||
		gap.GetGap().GetReason() != agentv1.GapReason_GAP_REASON_QUEUE_FULL {
		t.Fatalf("gap = %+v", gap)
	}
	if gap.GetGap().LostEvents != nil {
		t.Fatal("the size of an unknown loss must stay unknown")
	}
}

func TestUnparseableLinesBecomeAGap(t *testing.T) {
	reader := &scriptedReader{batches: []Batch{{Unparseable: 3, Cursor: []byte("after")}}}
	item, events := newTestCollector(t, reader, 1<<20)
	item.tick(context.Background())

	items, err := events.Peek(10, 1<<20)
	if err != nil || len(items) != 1 {
		t.Fatalf("items = %d, %v", len(items), err)
	}
	gap := items[0].Event.GetGap()
	if gap.GetReason() != agentv1.GapReason_GAP_REASON_UNPARSEABLE_RECORDS || gap.GetLostEvents() != 3 {
		t.Fatalf("gap = %+v", gap)
	}
	if item.Health().GetLostEventsTotal() != 3 {
		t.Fatalf("health = %+v", item.Health())
	}
}

func TestSilentSourceIsObservingBrokenSourceIsNot(t *testing.T) {
	item, _ := newTestCollector(t, &scriptedReader{}, 1<<20)
	if item.Health().GetState() == agentv1.AuditSourceState_AUDIT_SOURCE_STATE_OBSERVING {
		t.Fatal("nothing was read yet")
	}
	item.tick(context.Background())
	health := item.Health()
	if health.GetState() != agentv1.AuditSourceState_AUDIT_SOURCE_STATE_OBSERVING || health.GetPositionReadAt() == nil {
		t.Fatalf("health = %+v", health)
	}

	missing := filepath.Join(t.TempDir(), "absent")
	broken, _ := newTestCollector(t, NewPostgresReader(missing), 1<<20)
	broken.tick(context.Background())
	if state := broken.Health().GetState(); state == agentv1.AuditSourceState_AUDIT_SOURCE_STATE_OBSERVING {
		t.Fatalf("state = %s", state)
	}
}

func TestReplayedRecordKeepsItsEventID(t *testing.T) {
	item, _ := newTestCollector(t, &scriptedReader{}, 1<<20)
	item.tick(context.Background())
	first, _ := item.event(&Record{Position: "7:100", Statement: NewStatement("SELECT id FROM users"), Status: agentv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS})
	second, _ := item.event(&Record{Position: "7:100", Statement: NewStatement("SELECT id FROM users"), Status: agentv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS})
	other, _ := item.event(&Record{Position: "7:101", Statement: NewStatement("SELECT id FROM users"), Status: agentv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS})
	if first.GetEventId() != second.GetEventId() || first.GetEventId() == other.GetEventId() {
		t.Fatal("event id must follow the log position")
	}
}

func TestLiteralNeverReachesTheEvent(t *testing.T) {
	item, _ := newTestCollector(t, &scriptedReader{}, 1<<20)
	item.tick(context.Background())
	record := statementRecord(1)
	event, _ := item.event(&record)
	if event == nil {
		t.Fatal("no event")
	}
	if strings.Contains(event.String(), "dgcanary") {
		t.Fatalf("value in event: %s", event)
	}
}

type pagedAudit struct {
	rows []connector.AuditRow
	page int
}

// AuditRows mimics fn_get_audit_file: it starts at the given offset, inclusive.
func (p *pagedAudit) AuditRows(_ context.Context, _, file string, offset int64) ([]connector.AuditRow, error) {
	start := 0
	if file != "" {
		for start < len(p.rows) && (p.rows[start].File != file || p.rows[start].Offset < offset) {
			start++
		}
	}
	return p.rows[start:min(len(p.rows), start+p.page)], nil
}

func TestSQLServerFreshStartSkipsAllHistory(t *testing.T) {
	audit := &pagedAudit{page: 3}
	for i := range 10 {
		audit.rows = append(audit.rows, connector.AuditRow{
			File: "a.sqlaudit", Offset: int64(i / 2), Sequence: 1, Session: i, UserObject: true, Statement: "SELECT id FROM users",
		})
	}
	reader := &sqlServerReader{source: audit, pattern: "*"}
	first, err := reader.Read(context.Background(), nil)
	if err != nil || len(first.Records) != 0 {
		t.Fatalf("fresh start replayed history: %d records, %v", len(first.Records), err)
	}
	audit.rows = append(audit.rows, connector.AuditRow{
		File: "a.sqlaudit", Offset: 4, Sequence: 1, Session: 99, UserObject: true, Statement: "SELECT id FROM users",
	})
	next, err := reader.Read(context.Background(), first.Cursor)
	if err != nil || len(next.Records) != 1 || next.Records[0].Session != "99" {
		t.Fatalf("records = %+v, %v", next.Records, err)
	}
}

func TestSQLServerResumeInsideASharedOffsetDeliversEachRecordOnce(t *testing.T) {
	audit := &pagedAudit{page: 100}
	row := func(session int) connector.AuditRow {
		return connector.AuditRow{File: "a.sqlaudit", Offset: 7, Sequence: 1, Session: session, UserObject: true, Statement: "SELECT id FROM users"}
	}
	reader := &sqlServerReader{source: audit, pattern: "*"}
	start, err := reader.Read(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	cursor := start.Cursor
	delivered := map[string]bool{}
	for step := range 4 {
		audit.rows = append(audit.rows, row(step))
		batch, err := reader.Read(context.Background(), cursor)
		if err != nil {
			t.Fatal(err)
		}
		for _, record := range batch.Records {
			if delivered[record.Position] {
				t.Fatalf("step %d: %s delivered twice", step, record.Position)
			}
			delivered[record.Position] = true
		}
		cursor = batch.Cursor
	}
	if len(delivered) != 4 {
		t.Fatalf("delivered %d of 4", len(delivered))
	}
}

func TestBlockedEventBecomesAGap(t *testing.T) {
	record := statementRecord(1)
	record.Principal = "bad\nname"
	reader := &scriptedReader{batches: []Batch{{Records: []Record{record}, Cursor: []byte("after")}}}
	item, events := newTestCollector(t, reader, 1<<20)
	item.tick(context.Background())
	items, err := events.Peek(10, 1<<20)
	if err != nil || len(items) != 1 || items[0].Event.GetGap().GetLostEvents() != 1 {
		t.Fatalf("items = %+v, %v", items, err)
	}
}

func TestHeldSessionOverflowReleasesInsteadOfDropping(t *testing.T) {
	parser := newPostgresParser()
	var released []Record
	for i := range maxHeldSessions + 5 {
		released = append(released, feed(t, parser, map[string]any{
			"session_id": fmt.Sprintf("s%d", i), "vxid": "1/1", "message": audit("SELECT 1"),
		}, int64(i))...)
	}
	if len(released) != 5 || len(parser.held) != maxHeldSessions {
		t.Fatalf("released %d, held %d", len(released), len(parser.held))
	}
}

// After rotation the held records sit in two files. The durable cursor must
// point at the earlier one, or a crash would skip it.
func TestOldestHeldSpansRotatedFiles(t *testing.T) {
	for range 20 {
		parser := newPostgresParser()
		older := pgLine(t, map[string]any{"session_id": "s1", "vxid": "1/1", "message": audit("SELECT 1")})
		newer := pgLine(t, map[string]any{"session_id": "s2", "vxid": "2/1", "message": audit("SELECT 2")})
		parser.feed(older, fileCursor{Inode: 7, Offset: 900})
		parser.feed(newer, fileCursor{Inode: 8, Offset: 10})
		oldest, found := parser.oldestHeld()
		if !found || oldest != (fileCursor{Inode: 7, Offset: 900}) {
			t.Fatalf("oldest = %+v, want the record in the rotated file", oldest)
		}
	}
}

// A time fixed before queueing is what makes a redelivery recognizable at the
// center (ADR-0007), so an implausible log time must not travel as is.
func TestImplausibleLogTimeIsReplacedBeforeQueueing(t *testing.T) {
	now := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	for _, testCase := range []struct {
		at   time.Time
		kept bool
	}{
		{now.Add(-time.Hour), true},
		{now.Add(30 * time.Second), true},
		{now.Add(2 * time.Minute), false},
		{now.Add(-365 * 24 * time.Hour), false},
		{time.Unix(0, 0), false},
	} {
		got := plausibleTime(testCase.at, now)
		if testCase.kept != got.Equal(testCase.at) || !testCase.kept && !got.Equal(now) {
			t.Errorf("plausibleTime(%s) = %s", testCase.at, got)
		}
	}
}

// Every way the collector learns of a loss reaches the metrics, so a scraper sees
// blindness without reading the center (ADR-0008).
func TestEveryGapIsCounted(t *testing.T) {
	var records []Record
	for i := range 50 {
		records = append(records, statementRecord(i))
	}
	observer := telemetry.New()
	reader := &scriptedReader{batches: []Batch{{Unparseable: 3, Cursor: []byte("first")}, {Gap: lostLogGap(), Cursor: []byte("second")}}}
	item, _ := newTestCollector(t, reader, 1<<20)
	item.options.Metrics = observer
	item.tick(context.Background())
	item.tick(context.Background())

	full := &scriptedReader{batches: []Batch{{Records: records, Cursor: []byte("after")}}}
	blocked, _ := newTestCollector(t, full, 512)
	blocked.options.Metrics = observer
	blocked.tick(context.Background())
	full.batches = []Batch{{Gap: lostLogGap(), Cursor: []byte("resumed")}}
	full.position = 0
	blocked.tick(context.Background())

	samples, err := observer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]float64{
		"dataguard_agent_audit_gaps_total|reason=GAP_REASON_UNPARSEABLE_RECORDS":        1,
		"dataguard_agent_audit_lost_events_total|reason=GAP_REASON_UNPARSEABLE_RECORDS": 3,
		"dataguard_agent_audit_gaps_total|reason=GAP_REASON_LOG_ROTATED":                1,
		"dataguard_agent_audit_gaps_total|reason=GAP_REASON_QUEUE_FULL":                 1,
		"dataguard_agent_events_queued_total|type=EVENT_TYPE_AUDIT_GAP":                 3,
	} {
		if samples[key] != want {
			t.Errorf("%s = %v, want %v", key, samples[key], want)
		}
	}
}
