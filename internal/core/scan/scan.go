// Package scan schedules discovery jobs and applies their results to the
// catalog.
package scan

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/google/uuid"

	"dataguard/internal/core/asset"
	"dataguard/internal/core/oplog"
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

// Bounds of a schedule. An hour is the shortest period: a scan reads every
// table of the source, so running it more often loads the database for little
// news. Thirty days is the longest the reports look back.
const (
	MinScheduleHours = 1
	MaxScheduleHours = 720
	// maxFirstRunDistance keeps the first run within a year of now either way.
	maxFirstRunDistance = 366 * 24 * time.Hour
	// scheduleBatch is how many due sources of a tenant one run queues; the
	// rest wait for the next run.
	scheduleBatch = 100
)

var (
	ErrNotFound = errors.New("not found")
	ErrInvalid  = errors.New("invalid")
	// ErrStale means the result is for a job this agent no longer holds.
	ErrStale = errors.New("job is not running on this agent")
)

type Job struct {
	ID       uuid.UUID
	TenantID uuid.UUID
	SourceID uuid.UUID
	Status   string
	// RequestedBy is who asked for the scan; empty when Scheduled.
	RequestedBy string
	// Scheduled is a scan the center queued by itself, by the source's schedule.
	Scheduled   bool
	FailureCode string
	CreatedAt   time.Time
	StartedAt   *time.Time
	FinishedAt  *time.Time
}

// Schedule is when the center queues scans of a source by itself.
type Schedule struct {
	EveryHours int
	NextRun    time.Time
}

func (s Schedule) every() time.Duration { return time.Duration(s.EveryHours) * time.Hour }

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
	// CreateJob writes entry in the same transaction.
	CreateJob(ctx context.Context, job Job, entry oplog.Entry) error
	ListJobs(ctx context.Context, tenantID uuid.UUID, limit int) ([]Job, error)
	// LeaseJobs hands runnable jobs of this agent's sources to it.
	LeaseJobs(ctx context.Context, tenantID, agentID uuid.UUID, maxJobs int) ([]Job, error)
	// Complete runs build with the stored tables of the source, inside the
	// transaction that persists its result, so a concurrent scan cannot interleave.
	Complete(ctx context.Context, tenantID, agentID, jobID uuid.UUID, build func(existing []asset.Table) (Outcome, error)) error
	// SetSchedule stores the schedule of a saved, live source and writes entry
	// with it; entry gets the source's name as its label.
	SetSchedule(ctx context.Context, tenantID, sourceID uuid.UUID, schedule Schedule, entry oplog.Entry) error
	// ClearSchedule removes the schedule and writes entry, labelled like
	// SetSchedule's; a source without one is left as is, without an entry.
	ClearSchedule(ctx context.Context, tenantID, sourceID uuid.UUID, entry oplog.Entry) error
	// EnqueueScheduled takes up to limit saved sources of active agents whose
	// next run is at or before now, queues a scheduled job for each that has
	// none pending or running, and moves its next run to next(schedule). A
	// source taken by a concurrent call is skipped, not waited for. It returns
	// how many jobs it queued.
	EnqueueScheduled(ctx context.Context, tenantID uuid.UUID, now time.Time, limit int, next func(Schedule) time.Time) (int, error)
}

// Sources finds the source a scan is asked for.
type Sources interface {
	// ScannableSource returns the name of a saved, live source.
	ScannableSource(ctx context.Context, tenantID, sourceID uuid.UUID) (name string, found bool, err error)
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
	name, exists, err := s.sources.ScannableSource(ctx, tenantID, sourceID)
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
	if err := s.repository.CreateJob(ctx, job, oplog.New(ctx, oplog.ScanRequest, sourceID, name)); err != nil {
		return Job{}, err
	}
	return job, nil
}

func (s *Service) List(ctx context.Context, tenantID uuid.UUID, limit int) ([]Job, error) {
	return s.repository.ListJobs(ctx, tenantID, limit)
}

// SetSchedule makes the center scan the source every everyHours, first at
// firstRun. A first run in the past only sets the rhythm: the next run is the
// first moment of it still ahead, so "every day at 02:00" can be given as
// today at 02:00 at any time of day.
func (s *Service) SetSchedule(ctx context.Context, tenantID, sourceID uuid.UUID, everyHours int, firstRun time.Time) (Schedule, error) {
	now := time.Now().UTC()
	switch {
	case everyHours < MinScheduleHours || everyHours > MaxScheduleHours:
		return Schedule{}, fmt.Errorf("%w: a scan can repeat every %d..%d hours", ErrInvalid, MinScheduleHours, MaxScheduleHours)
	case firstRun.Before(now.Add(-maxFirstRunDistance)) || firstRun.After(now.Add(maxFirstRunDistance)):
		return Schedule{}, fmt.Errorf("%w: the first run must be within a year of now", ErrInvalid)
	}
	schedule := Schedule{EveryHours: everyHours}
	schedule.NextRun = NextRun(firstRun.UTC(), schedule.every(), now)
	entry := oplog.New(ctx, oplog.ScanScheduleUpdate, sourceID, "").With(oplog.DetailEveryHours, strconv.Itoa(everyHours))
	if err := s.repository.SetSchedule(ctx, tenantID, sourceID, schedule, entry); err != nil {
		return Schedule{}, err
	}
	return schedule, nil
}

// ClearSchedule leaves the source's scans to be started by hand.
func (s *Service) ClearSchedule(ctx context.Context, tenantID, sourceID uuid.UUID) error {
	return s.repository.ClearSchedule(ctx, tenantID, sourceID, oplog.New(ctx, oplog.ScanScheduleDelete, sourceID, ""))
}

// RunSchedules queues the scans of a tenant whose time has come and returns
// how many it queued. A source whose previous scan still waits or runs gets no
// second one: an agent offline for a week would otherwise come back to a week
// of scans. Runs missed while the server was down are made up by one scan, not
// one per missed run.
func (s *Service) RunSchedules(ctx context.Context, tenantID uuid.UUID) (int, error) {
	now := time.Now().UTC()
	return s.repository.EnqueueScheduled(ctx, tenantID, now, scheduleBatch, func(schedule Schedule) time.Time {
		return NextRun(schedule.NextRun, schedule.every(), now)
	})
}

// NextRun is the first moment after now of the rhythm that passes anchor every
// period; anchor itself when it is still ahead.
func NextRun(anchor time.Time, period time.Duration, now time.Time) time.Time {
	if anchor.After(now) {
		return anchor
	}
	return anchor.Add((now.Sub(anchor)/period + 1) * period)
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
