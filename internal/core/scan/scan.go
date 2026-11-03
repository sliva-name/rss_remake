// Package scan schedules discovery jobs and applies their results to the
// catalog.
package scan

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"dataguard/internal/core/asset"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

// Job statuses.
const (
	StatusPending   = "pending"
	StatusRunning   = "running"
	StatusCompleted = "completed"
	StatusPartial   = "partial"
	StatusFailed    = "failed"
	StatusCancelled = "cancelled"
)

// LeaseDuration outlasts the longest default budget, so a live agent is not
// raced by a retry; an agent that died releases the job when the lease expires.
const LeaseDuration = 15 * time.Minute

// MaxAttempts stops a job that keeps killing its agent from looping forever.
const MaxAttempts = 3

var (
	ErrNotFound = errors.New("not found")
	// ErrStale means the result is for a job this agent no longer holds.
	ErrStale = errors.New("job is not running on this agent")
)

type Job struct {
	ID          uuid.UUID
	TenantID    uuid.UUID
	SourceID    uuid.UUID
	Status      string
	RequestedBy string
	FailureCode string
	CreatedAt   time.Time
	StartedAt   *time.Time
	FinishedAt  *time.Time
}

// Classification is one finding bound to a stored column.
type Classification struct {
	ColumnID uuid.UUID
	Item     *agentv1.ColumnClassification
}

// Outcome is everything to persist when a job ends.
type Outcome struct {
	Status          string
	FailureCode     string
	Result          *agentv1.ScanResult
	Plan            asset.Plan
	Classifications []Classification
	// ProfiledTables holds tables read in full, the only ones where an absent
	// finding means the category is gone rather than not looked at.
	ProfiledTables []uuid.UUID
}

// Repository persists jobs and the catalog.
type Repository interface {
	CreateJob(ctx context.Context, job Job) error
	ListJobs(ctx context.Context, tenantID uuid.UUID, limit int) ([]Job, error)
	// LeaseJobs hands runnable jobs of this agent's sources to it.
	LeaseJobs(ctx context.Context, tenantID, agentID uuid.UUID, maxJobs int) ([]Job, error)
	// Complete runs build with the stored tables of the source, inside the
	// transaction that persists its result, so a concurrent scan cannot interleave.
	Complete(ctx context.Context, tenantID, agentID, jobID uuid.UUID, build func(existing []asset.Table) (Outcome, error)) error
}

// Sources checks that a source exists for the tenant.
type Sources interface {
	SourceExists(ctx context.Context, tenantID, sourceID uuid.UUID) (bool, error)
}

type Service struct {
	repository Repository
	sources    Sources
}

func NewService(repository Repository, sources Sources) *Service {
	return &Service{repository: repository, sources: sources}
}

// Request queues a scan.
func (s *Service) Request(ctx context.Context, tenantID, sourceID uuid.UUID, requestedBy string) (Job, error) {
	exists, err := s.sources.SourceExists(ctx, tenantID, sourceID)
	if err != nil {
		return Job{}, err
	}
	if !exists {
		return Job{}, ErrNotFound
	}
	job := Job{
		ID: uuid.Must(uuid.NewV7()), TenantID: tenantID, SourceID: sourceID, Status: StatusPending,
		RequestedBy: requestedBy, CreatedAt: time.Now().UTC(),
	}
	if err := s.repository.CreateJob(ctx, job); err != nil {
		return Job{}, err
	}
	return job, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID, limit int) ([]Job, error) {
	return s.repository.ListJobs(ctx, tenantID, limit)
}

// Lease gives an agent its next jobs.
func (s *Service) Lease(ctx context.Context, tenantID, agentID uuid.UUID, maxJobs int) ([]Job, error) {
	return s.repository.LeaseJobs(ctx, tenantID, agentID, maxJobs)
}

// Complete applies a result. A failed scan changes nothing in the catalog: its
// empty snapshot says nothing about the database and must not remove objects.
func (s *Service) Complete(ctx context.Context, tenantID, agentID uuid.UUID, result *agentv1.ScanResult) error {
	jobID, err := uuid.Parse(result.GetJobId())
	if err != nil {
		return ErrStale
	}
	return s.repository.Complete(ctx, tenantID, agentID, jobID, func(existing []asset.Table) (Outcome, error) {
		return buildOutcome(existing, result), nil
	})
}

func buildOutcome(existing []asset.Table, result *agentv1.ScanResult) Outcome {
	outcome := Outcome{Status: statusOf(result.GetOutcome()), FailureCode: result.GetFailureCode(), Result: result}
	if outcome.Status != StatusCompleted && outcome.Status != StatusPartial {
		return outcome
	}
	outcome.Plan = asset.Reconcile(existing, snapshotTables(result))

	columnIDs := map[string]uuid.UUID{}
	tableIDs := map[string]uuid.UUID{}
	for _, table := range outcome.Plan.Tables {
		if table.Status != asset.StatusActive {
			continue
		}
		tableIDs[tableKey(table.Database, table.Schema, table.Name)] = table.ID
		for _, column := range table.Columns {
			if column.Status == asset.StatusActive {
				columnIDs[columnKey(table.Database, table.Schema, table.Name, column.Name)] = column.ID
			}
		}
	}
	for _, item := range result.GetClassifications() {
		path := item.GetColumn().GetTable()
		key := columnKey(path.GetDatabase(), path.GetSchema(), path.GetTable(), item.GetColumn().GetColumn())
		if id, ok := columnIDs[key]; ok {
			outcome.Classifications = append(outcome.Classifications, Classification{ColumnID: id, Item: item})
		}
	}
	skipped := map[string]bool{}
	for _, table := range result.GetSkippedTables() {
		path := table.GetTable()
		skipped[tableKey(path.GetDatabase(), path.GetSchema(), path.GetTable())] = true
	}
	for key, id := range tableIDs {
		if !skipped[key] {
			outcome.ProfiledTables = append(outcome.ProfiledTables, id)
		}
	}
	return outcome
}

func snapshotTables(result *agentv1.ScanResult) []asset.Table {
	tables := make([]asset.Table, 0, len(result.GetTables()))
	for _, snapshot := range result.GetTables() {
		path := snapshot.GetPath()
		table := asset.Table{
			Database: path.GetDatabase(), Schema: path.GetSchema(), Name: path.GetTable(),
			Kind: snapshot.GetKind().String(), Status: asset.StatusActive,
		}
		for _, column := range snapshot.GetColumns() {
			table.Columns = append(table.Columns, asset.Column{
				Name: column.GetName(), NativeType: column.GetNativeType(), Ordinal: int32(column.GetOrdinal()),
				Nullable: column.GetNullable(), Status: asset.StatusActive,
			})
		}
		tables = append(tables, table)
	}
	return tables
}

func statusOf(outcome agentv1.ScanOutcome) string {
	switch outcome {
	case agentv1.ScanOutcome_SCAN_OUTCOME_COMPLETED:
		return StatusCompleted
	case agentv1.ScanOutcome_SCAN_OUTCOME_PARTIAL:
		return StatusPartial
	case agentv1.ScanOutcome_SCAN_OUTCOME_CANCELLED:
		return StatusCancelled
	default:
		return StatusFailed
	}
}

func tableKey(database, schema, name string) string {
	return database + "\x00" + schema + "\x00" + name
}

func columnKey(database, schema, table, column string) string {
	return tableKey(database, schema, table) + "\x00" + column
}
