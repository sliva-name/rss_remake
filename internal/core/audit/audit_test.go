package audit_test

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"dataguard/internal/core/audit"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

type fakeCatalog struct {
	owned   []uuid.UUID
	columns map[audit.ColumnKey]audit.ColumnInfo
}

func (f fakeCatalog) AgentSources(context.Context, uuid.UUID, uuid.UUID) ([]uuid.UUID, error) {
	return f.owned, nil
}

func (f fakeCatalog) CatalogVersion(context.Context, uuid.UUID, uuid.UUID) (time.Time, error) {
	return time.Time{}, nil
}

func (f fakeCatalog) ColumnsOf(context.Context, uuid.UUID, uuid.UUID) (map[audit.ColumnKey]audit.ColumnInfo, error) {
	return f.columns, nil
}

type fakeSink struct {
	events []audit.Event
	err    error
	locks  *fakeLocks
}

func (f *fakeSink) Stored(_ context.Context, _ uuid.UUID, keys []audit.EventKey) (map[uuid.UUID]bool, error) {
	f.locks.requireHeld()
	stored := map[uuid.UUID]bool{}
	for _, key := range keys {
		for _, event := range f.events {
			if event.ID == key.ID && event.Time.Equal(key.Time) {
				stored[key.ID] = true
			}
		}
	}
	return stored, nil
}

func (f *fakeSink) Insert(_ context.Context, events []audit.Event) error {
	f.locks.requireHeld()
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, events...)
	return nil
}

type fakeLocks struct {
	t    *testing.T
	held bool
}

func (f *fakeLocks) WithAgentLock(ctx context.Context, _, _ uuid.UUID, work func(context.Context) error) error {
	f.held = true
	defer func() { f.held = false }()
	return work(ctx)
}

func (f *fakeLocks) requireHeld() {
	if !f.held {
		f.t.Error("the store was used outside the agent lock")
	}
}

// directPublisher stores at once, standing in for the broker and its consumer.
type directPublisher struct {
	service *audit.Service
}

func (p *directPublisher) Publish(ctx context.Context, events []audit.Event) error {
	return p.service.Store(ctx, events)
}

func newService(t *testing.T, catalog audit.Catalog) (*audit.Service, *fakeSink) {
	locks := &fakeLocks{t: t}
	sink := &fakeSink{locks: locks}
	publisher := &directPublisher{}
	publisher.service = audit.NewService(catalog, locks, sink, publisher, nil)
	return publisher.service, sink
}

func event(sourceID uuid.UUID) *agentv1.AuditEvent {
	table := &agentv1.TablePath{Database: "crm", Schema: "public", Table: "users"}
	return &agentv1.AuditEvent{
		EventId: uuid.NewString(), SourceId: sourceID.String(), EventTime: timestamppb.Now(),
		EventType: agentv1.EventType_EVENT_TYPE_DATA_ACCESS,
		Operation: &agentv1.Operation{
			Type:   agentv1.OperationType_OPERATION_TYPE_SELECT,
			Tables: []*agentv1.TablePath{table},
			Columns: []*agentv1.AccessedColumn{
				{Column: &agentv1.ColumnPath{Table: table, Column: "email"}, Read: true},
				{Column: &agentv1.ColumnPath{Table: table, Column: "inn"}, Read: true},
				{Column: &agentv1.ColumnPath{Table: table, Column: "unknown"}, Read: true},
			},
		},
	}
}

func TestIngestStampsCategoriesFromTheCatalog(t *testing.T) {
	sourceID := uuid.New()
	email, inn := uuid.New(), uuid.New()
	service, sink := newService(t, fakeCatalog{owned: []uuid.UUID{sourceID}, columns: map[audit.ColumnKey]audit.ColumnInfo{
		{Database: "crm", Schema: "public", Table: "users", Column: "email"}: {ID: email, Categories: []string{"PERSONAL.EMAIL"}},
		{Database: "crm", Schema: "public", Table: "users", Column: "inn"}:   {ID: inn, Categories: []string{"GOVERNMENT.TAX_ID"}},
	}})
	item := event(sourceID)

	accepted, err := service.Ingest(t.Context(), uuid.New(), uuid.New(), []*agentv1.AuditEvent{item})
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(accepted) != 1 || accepted[0] != item.GetEventId() {
		t.Fatalf("accepted = %v", accepted)
	}
	stored := sink.events[0]
	if !reflect.DeepEqual(stored.Categories, []string{"GOVERNMENT.TAX_ID", "PERSONAL.EMAIL"}) {
		t.Fatalf("categories = %v", stored.Categories)
	}
	if !reflect.DeepEqual(stored.ColumnIDs, []uuid.UUID{email, inn}) {
		t.Fatalf("column ids = %v", stored.ColumnIDs)
	}
	if len(stored.Columns) != 3 {
		t.Fatalf("an unclassified column must stay in the record: %v", stored.Columns)
	}
}

func TestIngestRefusesForeignSource(t *testing.T) {
	service, sink := newService(t, fakeCatalog{owned: []uuid.UUID{uuid.New()}})
	_, err := service.Ingest(t.Context(), uuid.New(), uuid.New(), []*agentv1.AuditEvent{event(uuid.New())})
	if !errors.Is(err, audit.ErrForeignSource) {
		t.Fatalf("err = %v", err)
	}
	if len(sink.events) != 0 {
		t.Fatal("nothing may be stored")
	}
}

func TestIngestAcknowledgesNothingWhenStorageFails(t *testing.T) {
	sourceID := uuid.New()
	service, sink := newService(t, fakeCatalog{owned: []uuid.UUID{sourceID}})
	sink.err = errors.New("unavailable")
	accepted, err := service.Ingest(t.Context(), uuid.New(), uuid.New(), []*agentv1.AuditEvent{event(sourceID)})
	if err == nil || accepted != nil {
		t.Fatalf("accepted = %v, err = %v", accepted, err)
	}
}

func TestGapKeepsUnknownLossUnknown(t *testing.T) {
	sourceID := uuid.New()
	service, sink := newService(t, fakeCatalog{owned: []uuid.UUID{sourceID}})
	gap := &agentv1.AuditEvent{
		EventId: uuid.NewString(), SourceId: sourceID.String(), EventTime: timestamppb.Now(),
		EventType: agentv1.EventType_EVENT_TYPE_AUDIT_GAP,
		Gap:       &agentv1.AuditGap{Reason: agentv1.GapReason_GAP_REASON_LOG_ROTATED},
	}
	if _, err := service.Ingest(t.Context(), uuid.New(), uuid.New(), []*agentv1.AuditEvent{gap}); err != nil {
		t.Fatal(err)
	}
	if sink.events[0].GapLostEvents != nil || sink.events[0].GapReason != "GAP_REASON_LOG_ROTATED" {
		t.Fatalf("event = %+v", sink.events[0])
	}
}

func TestImplausibleEventTimeIsReplaced(t *testing.T) {
	sourceID := uuid.New()
	service, sink := newService(t, fakeCatalog{owned: []uuid.UUID{sourceID}})
	for _, at := range []time.Time{time.Unix(0, 0), time.Now().Add(100 * 365 * 24 * time.Hour)} {
		item := event(sourceID)
		item.EventTime = timestamppb.New(at)
		if _, err := service.Ingest(t.Context(), uuid.New(), uuid.New(), []*agentv1.AuditEvent{item}); err != nil {
			t.Fatal(err)
		}
	}
	for _, stored := range sink.events {
		if time.Since(stored.Time) > time.Minute {
			t.Fatalf("kept an implausible time: %s", stored.Time)
		}
	}
}

type countingCatalog struct {
	fakeCatalog
	versionReads map[uuid.UUID]int
}

func (c *countingCatalog) CatalogVersion(_ context.Context, _, sourceID uuid.UUID) (time.Time, error) {
	c.versionReads[sourceID]++
	return time.Time{}, nil
}

// Each lookup is a transaction in PostgreSQL, so a batch must not pay one per event.
func TestIngestReadsEachCatalogOncePerBatch(t *testing.T) {
	first, second := uuid.New(), uuid.New()
	catalog := &countingCatalog{owned: []uuid.UUID{first, second}, versionReads: map[uuid.UUID]int{}}
	service, _ := newService(t, catalog)
	batch := []*agentv1.AuditEvent{event(first), event(second), event(first), event(first), event(second)}
	if _, err := service.Ingest(t.Context(), uuid.New(), uuid.New(), batch); err != nil {
		t.Fatal(err)
	}
	if catalog.versionReads[first] != 1 || catalog.versionReads[second] != 1 {
		t.Fatalf("catalog version reads = %v, want one per source", catalog.versionReads)
	}
}

func TestRedeliveryIsAcknowledgedButStoredOnce(t *testing.T) {
	sourceID := uuid.New()
	service, sink := newService(t, fakeCatalog{owned: []uuid.UUID{sourceID}})
	first, second := event(sourceID), event(sourceID)
	if _, err := service.Ingest(t.Context(), uuid.New(), uuid.New(), []*agentv1.AuditEvent{first}); err != nil {
		t.Fatal(err)
	}
	accepted, err := service.Ingest(t.Context(), uuid.New(), uuid.New(), []*agentv1.AuditEvent{first, second, second})
	if err != nil {
		t.Fatal(err)
	}
	if len(accepted) != 3 {
		t.Fatalf("accepted = %v, every delivered id must be acknowledged", accepted)
	}
	if len(sink.events) != 2 || sink.events[1].ID.String() != second.GetEventId() {
		t.Fatalf("stored %d events, want the first once and the second once", len(sink.events))
	}
}

// A redelivery must find the stored row by the key storage actually keeps.
func TestEventTimeIsKeptToTheMicrosecond(t *testing.T) {
	sourceID := uuid.New()
	service, sink := newService(t, fakeCatalog{owned: []uuid.UUID{sourceID}})
	item := event(sourceID)
	item.EventTime = timestamppb.New(time.Now().Truncate(time.Microsecond).Add(789 * time.Nanosecond))
	for range 2 {
		if _, err := service.Ingest(t.Context(), uuid.New(), uuid.New(), []*agentv1.AuditEvent{item}); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.events) != 1 || sink.events[0].Time.Nanosecond()%1000 != 0 {
		t.Fatalf("stored %d events, time %s", len(sink.events), sink.events[0].Time)
	}
}

// A consumer reads events of many agents at once; each agent is stored under its
// own lock, and a record read twice is stored once.
func TestStoreSeparatesAgentsAndDropsRepeats(t *testing.T) {
	locks := &countingLocks{t: t, agents: map[uuid.UUID]int{}}
	sink := &fakeSink{locks: &locks.fakeLocks}
	service := audit.NewService(fakeCatalog{}, locks, sink, nil, nil)
	tenantID, first, second := uuid.New(), uuid.New(), uuid.New()
	at := time.Now().UTC().Truncate(time.Microsecond)
	repeated := audit.Event{ID: uuid.New(), TenantID: tenantID, AgentID: first, Time: at}
	batch := []audit.Event{repeated, {ID: uuid.New(), TenantID: tenantID, AgentID: second, Time: at}, repeated}
	for range 2 {
		if err := service.Store(t.Context(), batch); err != nil {
			t.Fatal(err)
		}
	}
	if len(sink.events) != 2 {
		t.Fatalf("stored %d events, want 2", len(sink.events))
	}
	if locks.agents[first] != 2 || locks.agents[second] != 2 {
		t.Fatalf("locks taken = %v, want one per agent per call", locks.agents)
	}
}

type countingLocks struct {
	fakeLocks
	agents map[uuid.UUID]int
}

func (c *countingLocks) WithAgentLock(ctx context.Context, tenantID, agentID uuid.UUID, work func(context.Context) error) error {
	c.agents[agentID]++
	return c.fakeLocks.WithAgentLock(ctx, tenantID, agentID, work)
}
