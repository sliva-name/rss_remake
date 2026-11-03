package collector

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"dataguard/internal/agent/queue"
	"dataguard/internal/connector"
	"dataguard/internal/contract/egress"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/retry"
	"dataguard/internal/platform/safeerr"
	"dataguard/internal/query"
	"dataguard/internal/query/ir"
)

const (
	defaultPollInterval    = time.Second
	catalogRefreshInterval = 5 * time.Minute
	analysisCacheEntries   = 4096
	reasonQueueFull        = "QUEUE_FULL"
	reasonLogUnreadable    = "LOG_UNREADABLE"
	reasonCatalogFailed    = "CATALOG_UNAVAILABLE"
)

// eventNamespace scopes event ids to DataGuard.
var eventNamespace = uuid.MustParse("6f0b3c1e-52a4-4a0d-9f43-0d6a2b6f1c77")

func lostLogGap() *agentv1.AuditGap {
	return &agentv1.AuditGap{Reason: agentv1.GapReason_GAP_REASON_LOG_ROTATED}
}

// Verifier checks a signed application context.
type Verifier interface {
	Verify(token, databasePrincipal string, at time.Time) (subject, application, trace string, err error)
}

// Options configures a collector for one source.
type Options struct {
	SourceKey    string
	SourceID     string
	Reader       Reader
	Catalog      connector.Catalog
	Frontend     ir.Frontend
	Schema       string
	FoldCase     bool
	Queue        *queue.Queue
	Verifier     Verifier
	PollInterval time.Duration
	Logger       *slog.Logger
}

// Collector moves records from a log into the durable queue.
type Collector struct {
	options Options

	mu          sync.Mutex
	state       agentv1.AuditSourceState
	reason      string
	positionAt  time.Time
	lost        uint64
	queueFull   bool
	catalog     *query.CachedCatalog
	refreshedAt time.Time
}

// New creates a collector in the state of not having read anything yet.
func New(options Options) *Collector {
	if options.PollInterval == 0 {
		options.PollInterval = defaultPollInterval
	}
	return &Collector{options: options, state: agentv1.AuditSourceState_AUDIT_SOURCE_STATE_UNAVAILABLE, reason: "NOT_STARTED"}
}

// Health reports what the center should show. Quiet in OBSERVING means no
// activity; quiet in any other state means the source cannot be seen.
func (c *Collector) Health() *agentv1.AuditSourceHealth {
	c.mu.Lock()
	defer c.mu.Unlock()
	health := &agentv1.AuditSourceHealth{
		SourceId: c.options.SourceID, State: c.state, ReasonCode: c.reason, LostEventsTotal: c.lost,
	}
	if !c.positionAt.IsZero() {
		health.PositionReadAt = timestamppb.New(c.positionAt)
	}
	return health
}

func (c *Collector) setState(state agentv1.AuditSourceState, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state, c.reason = state, reason
}

// Run reads until ctx ends. An unreadable log is a state, not a reason to stop:
// the agent keeps retrying and reports it.
func (c *Collector) Run(ctx context.Context) {
	for {
		c.tick(ctx)
		if !retry.Sleep(ctx, c.options.PollInterval) {
			return
		}
	}
}

func (c *Collector) tick(ctx context.Context) {
	if err := c.refreshCatalog(ctx); err != nil {
		c.setState(agentv1.AuditSourceState_AUDIT_SOURCE_STATE_DEGRADED, reasonCatalogFailed)
		c.options.Logger.Warn("catalog refresh failed", "source_key", c.options.SourceKey, "error", err)
		return
	}
	cursor, err := c.options.Queue.Cursor(c.options.SourceKey)
	if err != nil {
		c.options.Logger.Error("read cursor", "source_key", c.options.SourceKey, "error", safeerr.New("read cursor", safeerr.CodeInternal, err))
		return
	}
	batch, err := c.options.Reader.Read(ctx, cursor)
	if err != nil {
		c.unreadable(err)
		return
	}
	if err := c.store(&batch); err != nil {
		c.options.Reader.Rewind()
		c.storeFailed(err)
		return
	}
	c.mu.Lock()
	c.state, c.reason, c.positionAt, c.queueFull = agentv1.AuditSourceState_AUDIT_SOURCE_STATE_OBSERVING, "", time.Now(), false
	c.lost += batch.Unparseable
	c.mu.Unlock()
}

func (c *Collector) unreadable(err error) {
	state := agentv1.AuditSourceState_AUDIT_SOURCE_STATE_UNAVAILABLE
	if errors.Is(err, os.ErrNotExist) {
		state = agentv1.AuditSourceState_AUDIT_SOURCE_STATE_NOT_CONFIGURED
	}
	c.setState(state, reasonLogUnreadable)
	c.options.Logger.Warn("audit log unreadable", "source_key", c.options.SourceKey, "code", string(safeerr.CodeOf(err)))
}

func (c *Collector) storeFailed(err error) {
	if errors.Is(err, queue.ErrFull) {
		// The cursor stays put, so records wait in the source log. They are lost only
		// if the log rotates first, and that is reported as a gap.
		c.mu.Lock()
		c.queueFull = true
		c.mu.Unlock()
		c.setState(agentv1.AuditSourceState_AUDIT_SOURCE_STATE_DEGRADED, reasonQueueFull)
		return
	}
	c.setState(agentv1.AuditSourceState_AUDIT_SOURCE_STATE_DEGRADED, "STORE_FAILED")
	c.options.Logger.Error("event not stored", "source_key", c.options.SourceKey, "error", safeerr.New("store events", safeerr.CodeInternal, err))
}

func (c *Collector) refreshCatalog(ctx context.Context) error {
	if c.catalog != nil && time.Since(c.refreshedAt) < catalogRefreshInterval {
		return nil
	}
	tables, err := c.options.Catalog.Tables(ctx)
	if err != nil {
		if c.catalog != nil {
			// A stale catalog beats no audit; names resolve against the last snapshot.
			c.refreshedAt = time.Now()
			return nil
		}
		return err
	}
	catalog := query.NewCatalog(c.options.Frontend, tables, c.options.Schema, c.options.FoldCase)
	c.catalog = query.NewCachedCatalog(catalog, analysisCacheEntries)
	c.refreshedAt = time.Now()
	return nil
}

func (c *Collector) store(batch *Batch) error {
	events, gaps := c.events(batch)
	if len(gaps) > 0 {
		if err := c.options.Queue.CommitGap(c.options.SourceKey, nil, gaps); err != nil {
			return err
		}
	}
	return c.options.Queue.Commit(c.options.SourceKey, batch.Cursor, events)
}

func (c *Collector) events(batch *Batch) (events, gaps []*agentv1.AuditEvent) {
	gapPosition := string(batch.Cursor)
	if batch.Gap != nil {
		c.mu.Lock()
		if c.queueFull {
			batch.Gap.Reason = agentv1.GapReason_GAP_REASON_QUEUE_FULL
		}
		c.mu.Unlock()
		gaps = append(gaps, c.gapEvent(batch.Gap, gapPosition))
	}
	if batch.Unparseable > 0 {
		lost := batch.Unparseable
		gaps = append(gaps, c.gapEvent(&agentv1.AuditGap{
			Reason: agentv1.GapReason_GAP_REASON_UNPARSEABLE_RECORDS, LostEvents: &lost,
		}, gapPosition+":unparseable"))
	}
	for i := range batch.Records {
		if event := c.event(&batch.Records[i]); event != nil {
			events = append(events, event)
		}
	}
	return events, gaps
}

func (c *Collector) gapEvent(gap *agentv1.AuditGap, position string) *agentv1.AuditEvent {
	now := timestamppb.Now()
	gap.ToTime = now
	return &agentv1.AuditEvent{
		EventId: c.eventID("gap:" + position), EventType: agentv1.EventType_EVENT_TYPE_AUDIT_GAP,
		EventTime: now, SourceId: c.options.SourceID, Gap: gap,
	}
}

func (c *Collector) eventID(position string) string {
	return uuid.NewSHA1(eventNamespace, []byte(c.options.SourceID+"\x00"+position)).String()
}

func (c *Collector) event(record *Record) *agentv1.AuditEvent {
	event := &agentv1.AuditEvent{
		EventId:   c.eventID(record.Position),
		EventTime: timestamppb.New(record.Time),
		SourceId:  c.options.SourceID,
		Actor:     c.actor(record),
		Execution: &agentv1.Execution{Status: record.Status, ErrorCode: record.ErrorCode},
		Correlation: &agentv1.Correlation{
			SessionId: record.Session, TransactionId: record.Transaction,
		},
	}
	if record.Kind == KindLogin {
		event.EventType = agentv1.EventType_EVENT_TYPE_AUTHENTICATION
		event.Operation = &agentv1.Operation{Type: agentv1.OperationType_OPERATION_TYPE_LOGIN}
		// A login names no objects, so there is nothing to resolve.
		event.Evidence = evidence(record.Status, agentv1.ObjectResolution_OBJECT_RESOLUTION_UNSPECIFIED)
		return c.checked(event)
	}
	analysis := c.catalog.Analyze(record.Statement.Reveal())
	if analysis.Internal {
		return nil
	}
	event.EventType = eventType(analysis.Operation, record.Status)
	event.Operation = operationOf(&analysis)
	event.Evidence = evidence(record.Status, analysis.Resolution)
	if trace := c.applyContext(event, record); trace != "" {
		event.Correlation.TraceId = trace
	}
	return c.checked(event)
}

// checked is a last check before the disk: the queue must hold nothing the wire
// would refuse. An event that fails is dropped and counted rather than stored,
// and the loss shows up in the source's lost events.
func (c *Collector) checked(event *agentv1.AuditEvent) *agentv1.AuditEvent {
	if err := egress.Check(event); err != nil {
		c.mu.Lock()
		c.lost++
		c.mu.Unlock()
		c.options.Logger.Error("event blocked", "source_key", c.options.SourceKey, "reason", "contract")
		return nil
	}
	return event
}

func (c *Collector) actor(record *Record) *agentv1.Actor {
	confidence := agentv1.IdentityConfidence_IDENTITY_CONFIDENCE_UNKNOWN
	if record.Principal != "" {
		confidence = agentv1.IdentityConfidence_IDENTITY_CONFIDENCE_DB_PRINCIPAL_ONLY
	}
	return &agentv1.Actor{
		DatabasePrincipal: record.Principal, IdentityConfidence: confidence,
		ClientAddress: normalizeAddress(record.ClientAddress),
	}
}

// normalizeAddress keeps literal addresses only. Host names are skipped: the
// server already resolved them and the contract carries addresses.
func normalizeAddress(address string) string {
	if err := egress.Check(&agentv1.Actor{ClientAddress: address}); err != nil {
		return ""
	}
	return address
}

// applyContext upgrades the actor only when the signature holds. A token that
// fails keeps its claim out of the event: the subject may be forged.
func (c *Collector) applyContext(event *agentv1.AuditEvent, record *Record) string {
	if record.ContextToken == "" {
		return ""
	}
	if c.options.Verifier == nil {
		event.Actor.IdentityConfidence = agentv1.IdentityConfidence_IDENTITY_CONFIDENCE_UNVERIFIED_CLAIM
		return ""
	}
	subject, application, trace, err := c.options.Verifier.Verify(record.ContextToken, record.Principal, record.Time)
	if err != nil {
		event.Actor.IdentityConfidence = agentv1.IdentityConfidence_IDENTITY_CONFIDENCE_UNVERIFIED_CLAIM
		return ""
	}
	event.Actor.ApplicationPrincipal = subject
	event.Actor.ApplicationId = application
	event.Actor.IdentityConfidence = agentv1.IdentityConfidence_IDENTITY_CONFIDENCE_VERIFIED
	return trace
}

func operationOf(analysis *query.Analysis) *agentv1.Operation {
	operation := &agentv1.Operation{Type: analysis.Operation, QueryFingerprint: analysis.Fingerprint}
	for _, table := range analysis.Tables {
		operation.Tables = append(operation.Tables, &agentv1.TablePath{
			Database: table.Database, Schema: table.Schema, Table: table.Name,
		})
	}
	for column, access := range analysis.Columns {
		operation.Columns = append(operation.Columns, &agentv1.AccessedColumn{
			Column: &agentv1.ColumnPath{
				Table:  &agentv1.TablePath{Database: column.Database, Schema: column.Schema, Table: column.Table},
				Column: column.Name,
			},
			Read: access.Read, Written: access.Written,
		})
	}
	return operation
}

func evidence(status agentv1.ExecutionStatus, resolution agentv1.ObjectResolution) *agentv1.Evidence {
	level := agentv1.EvidenceLevel_EVIDENCE_LEVEL_REFERENCED
	if status == agentv1.ExecutionStatus_EXECUTION_STATUS_SUCCESS {
		level = agentv1.EvidenceLevel_EVIDENCE_LEVEL_EXECUTED
	}
	return &agentv1.Evidence{
		Source: agentv1.EvidenceSource_EVIDENCE_SOURCE_NATIVE_AUDIT, Level: level, ObjectResolution: resolution,
	}
}

func eventType(operation agentv1.OperationType, status agentv1.ExecutionStatus) agentv1.EventType {
	if status == agentv1.ExecutionStatus_EXECUTION_STATUS_FAILURE {
		return agentv1.EventType_EVENT_TYPE_FAILED_ACCESS
	}
	switch operation {
	case agentv1.OperationType_OPERATION_TYPE_INSERT, agentv1.OperationType_OPERATION_TYPE_UPDATE,
		agentv1.OperationType_OPERATION_TYPE_MERGE:
		return agentv1.EventType_EVENT_TYPE_DATA_MODIFICATION
	case agentv1.OperationType_OPERATION_TYPE_DELETE:
		return agentv1.EventType_EVENT_TYPE_DATA_DELETION
	case agentv1.OperationType_OPERATION_TYPE_DDL:
		return agentv1.EventType_EVENT_TYPE_SCHEMA_CHANGE
	case agentv1.OperationType_OPERATION_TYPE_DCL:
		return agentv1.EventType_EVENT_TYPE_PERMISSION_CHANGE
	default:
		return agentv1.EventType_EVENT_TYPE_DATA_ACCESS
	}
}

// NewPostgresReader tails pgAudit's jsonlog in directory.
func NewPostgresReader(directory string) Reader {
	return newFileReader(filepath.Join(directory, "*.json"), newPostgresParser())
}

// NewMySQLReader tails the general log in directory.
func NewMySQLReader(directory string) Reader {
	return newFileReader(filepath.Join(directory, "general.log*"), newGeneralParser())
}

// NewMariaDBReader tails server_audit in directory.
func NewMariaDBReader(directory string) Reader {
	return newFileReader(filepath.Join(directory, "server_audit.log*"), mariadbParser{})
}

// NewSQLServerReader reads audit files through the connection.
func NewSQLServerReader(source connector.AuditLogSource, directory string) Reader {
	return &sqlServerReader{source: source, pattern: filepath.Join(directory, "*.sqlaudit")}
}
