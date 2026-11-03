package queue_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"dataguard/internal/agent/queue"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

func event(id int) *agentv1.AuditEvent {
	return &agentv1.AuditEvent{EventId: fmt.Sprintf("00000000-0000-4000-8000-%012d", id)}
}

func open(t *testing.T, directory string, capacity uint64) *queue.Queue {
	t.Helper()
	opened, err := queue.Open(directory, capacity)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return opened
}

func TestCommitIsAtomicWithCursor(t *testing.T) {
	directory := t.TempDir()
	first := open(t, directory, 1<<20)
	if err := first.Commit("crm", []byte("offset-1"), []*agentv1.AuditEvent{event(1), event(2)}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	reopened := open(t, directory, 1<<20)
	defer func() { _ = reopened.Close() }()
	cursor, err := reopened.Cursor("crm")
	if err != nil || string(cursor) != "offset-1" {
		t.Fatalf("Cursor = %q, %v", cursor, err)
	}
	items, err := reopened.Peek(10, 1<<20)
	if err != nil || len(items) != 2 {
		t.Fatalf("Peek = %d, %v", len(items), err)
	}
}

func TestPeekKeepsOrderAndAckRemoves(t *testing.T) {
	q := open(t, t.TempDir(), 1<<20)
	defer func() { _ = q.Close() }()
	if err := q.Commit("crm", nil, []*agentv1.AuditEvent{event(1), event(2), event(3)}); err != nil {
		t.Fatal(err)
	}
	items, err := q.Peek(2, 1<<20)
	if err != nil || len(items) != 2 || items[0].Event.GetEventId() != event(1).GetEventId() {
		t.Fatalf("Peek = %+v, %v", items, err)
	}
	if err := q.Ack([]uint64{items[0].Sequence, items[1].Sequence}); err != nil {
		t.Fatal(err)
	}
	stats, err := q.Stats()
	if err != nil || stats.PendingEvents != 1 {
		t.Fatalf("Stats = %+v, %v", stats, err)
	}
}

func TestFullQueueRefusesAndKeepsCursor(t *testing.T) {
	q := open(t, t.TempDir(), 200)
	defer func() { _ = q.Close() }()
	if err := q.Commit("crm", []byte("first"), []*agentv1.AuditEvent{event(1)}); err != nil {
		t.Fatal(err)
	}
	var batch []*agentv1.AuditEvent
	for i := range 20 {
		batch = append(batch, event(i))
	}
	if err := q.Commit("crm", []byte("second"), batch); !errors.Is(err, queue.ErrFull) {
		t.Fatalf("Commit = %v", err)
	}
	cursor, err := q.Cursor("crm")
	if err != nil || string(cursor) != "first" {
		t.Fatalf("cursor moved past refused events: %q, %v", cursor, err)
	}
	stats, err := q.Stats()
	if err != nil || stats.PendingEvents != 1 {
		t.Fatalf("a refused batch must store nothing: %+v, %v", stats, err)
	}
}

func TestGapIsStoredEvenWhenFull(t *testing.T) {
	q := open(t, t.TempDir(), 1)
	defer func() { _ = q.Close() }()
	if err := q.Commit("crm", nil, []*agentv1.AuditEvent{event(1)}); !errors.Is(err, queue.ErrFull) {
		t.Fatalf("Commit = %v", err)
	}
	if err := q.CommitGap("crm", nil, []*agentv1.AuditEvent{event(2)}); err != nil {
		t.Fatalf("CommitGap: %v", err)
	}
}

func TestFileHoldsNoPlaintext(t *testing.T) {
	directory := t.TempDir()
	q := open(t, directory, 1<<20)
	marker := "crm_service_marker"
	item := event(1)
	item.Actor = &agentv1.Actor{DatabasePrincipal: marker}
	if err := q.Commit("crm", nil, []*agentv1.AuditEvent{item}); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(directory, "queue.db"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte(marker)) {
		t.Fatal("queue file contains plaintext")
	}
}

func TestSizeIsRestoredAfterAck(t *testing.T) {
	q := open(t, t.TempDir(), 1<<20)
	defer func() { _ = q.Close() }()
	if err := q.Commit("crm", nil, []*agentv1.AuditEvent{event(1)}); err != nil {
		t.Fatal(err)
	}
	items, err := q.Peek(1, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.Ack([]uint64{items[0].Sequence, items[0].Sequence}); err != nil {
		t.Fatal(err)
	}
	stats, err := q.Stats()
	if err != nil || stats.PendingBytes != 0 {
		t.Fatalf("Stats = %+v, %v", stats, err)
	}
}
