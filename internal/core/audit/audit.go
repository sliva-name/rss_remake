// Package audit accepts events from agents and answers questions about access.
// An agent is an untrusted client: it can only report on its own sources, and
// classifications are attached here from the central catalog.
package audit

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"

	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

// ErrForeignSource means an event names a source the agent does not own.
var ErrForeignSource = errors.New("event names a source of another agent")

// Event is a stored audit event.
type Event struct {
	ID                   uuid.UUID
	TenantID             uuid.UUID
	AgentID              uuid.UUID
	SourceID             uuid.UUID
	Time                 time.Time
	Type                 string
	DatabasePrincipal    string
	ApplicationPrincipal string
	ApplicationID        string
	IdentityConfidence   string
	ClientAddress        string
	Operation            string
	Tables               []string
	Columns              []string
	ColumnIDs            []uuid.UUID
	Categories           []string
	QueryFingerprint     string
	ExecutionStatus      string
	ErrorCode            string
	EvidenceLevel        string
	ObjectResolution     string
	SessionID            string
	TransactionID        string
	TraceID              string
	GapReason            string
	GapLostEvents        *uint64
}

// ColumnInfo is what the catalog knows about a column.
type ColumnInfo struct {
	ID         uuid.UUID
	Categories []string
}

// ColumnKey addresses a column by its path in a source.
type ColumnKey struct {
	Database, Schema, Table, Column string
}

// Catalog resolves what an agent reports to stored objects.
type Catalog interface {
	// AgentSources lists the sources this agent may report on.
	AgentSources(ctx context.Context, tenantID, agentID uuid.UUID) ([]uuid.UUID, error)
	ColumnsOf(ctx context.Context, tenantID, sourceID uuid.UUID) (map[ColumnKey]ColumnInfo, error)
	// CatalogVersion changes whenever a scan of the source is applied.
	CatalogVersion(ctx context.Context, tenantID, sourceID uuid.UUID) (time.Time, error)
}

// Sink stores events. It returns only after they are durable, because the agent
// deletes its copy on acknowledgement.
type Sink interface {
	Insert(ctx context.Context, events []Event) error
}

const (
	// Event times outside this window are replaced by the arrival time. An agent's
	// clock is not trusted to pick a partition or to dodge the retention period.
	maxEventAge  = 365 * 24 * time.Hour
	maxClockSkew = 5 * time.Minute
)

type cachedColumns struct {
	columns map[ColumnKey]ColumnInfo
	version time.Time
}

// Service ingests events.
type Service struct {
	catalog Catalog
	sink    Sink
	now     func() time.Time

	mu    sync.Mutex
	cache map[uuid.UUID]cachedColumns
}

func NewService(catalog Catalog, sink Sink) *Service {
	return &Service{catalog: catalog, sink: sink, now: time.Now, cache: map[uuid.UUID]cachedColumns{}}
}

// columnsOf reuses a source's catalog until a scan changes it. Loading every
// column on every batch would put the catalog through PostgreSQL once a second,
// while a time-based cache would stamp stale categories right after a scan.
func (s *Service) columnsOf(ctx context.Context, tenantID, sourceID uuid.UUID) (map[ColumnKey]ColumnInfo, error) {
	version, err := s.catalog.CatalogVersion(ctx, tenantID, sourceID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	cached, found := s.cache[sourceID]
	s.mu.Unlock()
	if found && cached.version.Equal(version) {
		return cached.columns, nil
	}
	columns, err := s.catalog.ColumnsOf(ctx, tenantID, sourceID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.cache[sourceID] = cachedColumns{columns: columns, version: version}
	s.mu.Unlock()
	return columns, nil
}

// Ingest validates, enriches and stores a batch, returning accepted ids. The batch
// is all-or-nothing: an event for a foreign source means the agent is misbehaving.
func (s *Service) Ingest(ctx context.Context, tenantID, agentID uuid.UUID, events []*agentv1.AuditEvent) ([]string, error) {
	owned, err := s.catalog.AgentSources(ctx, tenantID, agentID)
	if err != nil {
		return nil, err
	}
	now := s.now()
	stored := make([]Event, 0, len(events))
	accepted := make([]string, 0, len(events))
	for _, event := range events {
		sourceID, err := uuid.Parse(event.GetSourceId())
		if err != nil || !slices.Contains(owned, sourceID) {
			return nil, ErrForeignSource
		}
		columns, err := s.columnsOf(ctx, tenantID, sourceID)
		if err != nil {
			return nil, err
		}
		converted, err := convert(tenantID, agentID, sourceID, event, columns)
		if err != nil {
			return nil, err
		}
		if converted.Time.Before(now.Add(-maxEventAge)) || converted.Time.After(now.Add(maxClockSkew)) {
			converted.Time = now
		}
		stored = append(stored, converted)
		accepted = append(accepted, event.GetEventId())
	}
	if err := s.sink.Insert(ctx, stored); err != nil {
		return nil, err
	}
	return accepted, nil
}

func convert(tenantID, agentID, sourceID uuid.UUID, event *agentv1.AuditEvent, columns map[ColumnKey]ColumnInfo) (Event, error) {
	id, err := uuid.Parse(event.GetEventId())
	if err != nil {
		return Event{}, fmt.Errorf("event id: %w", err)
	}
	actor, operation, evidence := event.GetActor(), event.GetOperation(), event.GetEvidence()
	converted := Event{
		ID: id, TenantID: tenantID, AgentID: agentID, SourceID: sourceID,
		Time:                 event.GetEventTime().AsTime(),
		Type:                 event.GetEventType().String(),
		DatabasePrincipal:    actor.GetDatabasePrincipal(),
		ApplicationPrincipal: actor.GetApplicationPrincipal(),
		ApplicationID:        actor.GetApplicationId(),
		IdentityConfidence:   actor.GetIdentityConfidence().String(),
		ClientAddress:        actor.GetClientAddress(),
		Operation:            operation.GetType().String(),
		QueryFingerprint:     operation.GetQueryFingerprint(),
		ExecutionStatus:      event.GetExecution().GetStatus().String(),
		ErrorCode:            event.GetExecution().GetErrorCode(),
		EvidenceLevel:        evidence.GetLevel().String(),
		ObjectResolution:     evidence.GetObjectResolution().String(),
		SessionID:            event.GetCorrelation().GetSessionId(),
		TransactionID:        event.GetCorrelation().GetTransactionId(),
		TraceID:              event.GetCorrelation().GetTraceId(),
	}
	if gap := event.GetGap(); gap != nil {
		converted.GapReason = gap.GetReason().String()
		converted.GapLostEvents = gap.LostEvents
	}
	for _, table := range operation.GetTables() {
		converted.Tables = append(converted.Tables, table.GetSchema()+"."+table.GetTable())
	}
	enrich(&converted, operation, columns)
	return converted, nil
}

// enrich stamps the classification known now. Later reclassification does not
// rewrite history: a report shows what was believed at the time of access.
func enrich(event *Event, operation *agentv1.Operation, columns map[ColumnKey]ColumnInfo) {
	categories := map[string]bool{}
	for _, accessed := range operation.GetColumns() {
		path := accessed.GetColumn().GetTable()
		name := accessed.GetColumn().GetColumn()
		event.Columns = append(event.Columns, path.GetSchema()+"."+path.GetTable()+"."+name)
		info, known := columns[ColumnKey{path.GetDatabase(), path.GetSchema(), path.GetTable(), name}]
		if !known {
			continue
		}
		event.ColumnIDs = append(event.ColumnIDs, info.ID)
		for _, category := range info.Categories {
			categories[category] = true
		}
	}
	for category := range categories {
		event.Categories = append(event.Categories, category)
	}
	slices.Sort(event.Categories)
}

// Filter narrows an event search; zero values mean no filter.
type Filter struct {
	SourceID  uuid.UUID
	Principal string
	Category  string
	Type      string
	// ExcludeType hides one type unless Type asks for it explicitly.
	ExcludeType string
	From        time.Time
	To          time.Time
	Limit       int
	Offset      int
}

// PrincipalAccess aggregates access by who did it.
type PrincipalAccess struct {
	DatabasePrincipal    string
	ApplicationPrincipal string
	IdentityConfidence   string
	Events               uint64
	SensitiveEvents      uint64
	Categories           []string
	Sources              uint64
	LastAccess           time.Time
}

// CategoryAccess aggregates access by data category.
type CategoryAccess struct {
	Category   string
	Events     uint64
	Principals uint64
	Sources    uint64
	LastAccess time.Time
}

// SourceWindow counts what the audit log showed for one source.
type SourceWindow struct {
	SourceID   uuid.UUID
	Statements uint64
	Resolved   uint64
	Verified   uint64
	Identified uint64
	Gaps       uint64
	LastEvent  time.Time
}

// Summary is the headline of a period.
type Summary struct {
	Events          uint64
	SensitiveEvents uint64
	FailedEvents    uint64
	Principals      uint64
	Gaps            uint64
}

// Reader answers questions about stored events.
type Reader interface {
	Search(ctx context.Context, tenantID uuid.UUID, filter Filter) ([]Event, uint64, error)
	ByPrincipal(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]PrincipalAccess, error)
	ByCategory(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]CategoryAccess, error)
	Windows(ctx context.Context, tenantID uuid.UUID, from, to time.Time) ([]SourceWindow, error)
	Summarize(ctx context.Context, tenantID uuid.UUID, from, to time.Time) (Summary, error)
}
