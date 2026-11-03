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
}

func (f *fakeSink) Insert(_ context.Context, events []audit.Event) error {
	f.events = append(f.events, events...)
	return f.err
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
	sink := &fakeSink{}
	service := audit.NewService(fakeCatalog{owned: []uuid.UUID{sourceID}, columns: map[audit.ColumnKey]audit.ColumnInfo{
		{Database: "crm", Schema: "public", Table: "users", Column: "email"}: {ID: email, Categories: []string{"PERSONAL.EMAIL"}},
		{Database: "crm", Schema: "public", Table: "users", Column: "inn"}:   {ID: inn, Categories: []string{"GOVERNMENT.TAX_ID"}},
	}}, sink)
	item := event(sourceID)

	accepted, err := service.Ingest(context.Background(), uuid.New(), uuid.New(), []*agentv1.AuditEvent{item})
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
	sink := &fakeSink{}
	service := audit.NewService(fakeCatalog{owned: []uuid.UUID{uuid.New()}}, sink)
	_, err := service.Ingest(context.Background(), uuid.New(), uuid.New(), []*agentv1.AuditEvent{event(uuid.New())})
	if !errors.Is(err, audit.ErrForeignSource) {
		t.Fatalf("err = %v", err)
	}
	if len(sink.events) != 0 {
		t.Fatal("nothing may be stored")
	}
}

func TestIngestAcknowledgesNothingWhenStorageFails(t *testing.T) {
	sourceID := uuid.New()
	sink := &fakeSink{err: errors.New("unavailable")}
	service := audit.NewService(fakeCatalog{owned: []uuid.UUID{sourceID}}, sink)
	accepted, err := service.Ingest(context.Background(), uuid.New(), uuid.New(), []*agentv1.AuditEvent{event(sourceID)})
	if err == nil || accepted != nil {
		t.Fatalf("accepted = %v, err = %v", accepted, err)
	}
}

func TestGapKeepsUnknownLossUnknown(t *testing.T) {
	sourceID := uuid.New()
	sink := &fakeSink{}
	service := audit.NewService(fakeCatalog{owned: []uuid.UUID{sourceID}}, sink)
	gap := &agentv1.AuditEvent{
		EventId: uuid.NewString(), SourceId: sourceID.String(), EventTime: timestamppb.Now(),
		EventType: agentv1.EventType_EVENT_TYPE_AUDIT_GAP,
		Gap:       &agentv1.AuditGap{Reason: agentv1.GapReason_GAP_REASON_LOG_ROTATED},
	}
	if _, err := service.Ingest(context.Background(), uuid.New(), uuid.New(), []*agentv1.AuditEvent{gap}); err != nil {
		t.Fatal(err)
	}
	if sink.events[0].GapLostEvents != nil || sink.events[0].GapReason != "GAP_REASON_LOG_ROTATED" {
		t.Fatalf("event = %+v", sink.events[0])
	}
}

func TestImplausibleEventTimeIsReplaced(t *testing.T) {
	sourceID := uuid.New()
	sink := &fakeSink{}
	service := audit.NewService(fakeCatalog{owned: []uuid.UUID{sourceID}}, sink)
	for _, at := range []time.Time{time.Unix(0, 0), time.Now().Add(100 * 365 * 24 * time.Hour)} {
		item := event(sourceID)
		item.EventTime = timestamppb.New(at)
		if _, err := service.Ingest(context.Background(), uuid.New(), uuid.New(), []*agentv1.AuditEvent{item}); err != nil {
			t.Fatal(err)
		}
	}
	for _, stored := range sink.events {
		if time.Since(stored.Time) > time.Minute {
			t.Fatalf("kept an implausible time: %s", stored.Time)
		}
	}
}
