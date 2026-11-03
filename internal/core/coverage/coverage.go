// Package coverage answers what the platform cannot see. A green status for a
// source audited only in part would be worse than none, so every number is
// measured, and a number with nothing behind it stays empty instead of zero.
package coverage

import (
	"context"
	"slices"
	"time"

	"github.com/google/uuid"

	"dataguard/internal/core/audit"
	"dataguard/internal/core/fleet"
)

// Status of observation.
const (
	// StatusObserving: reading works, so silence means no activity.
	StatusObserving = "OBSERVING"
	// StatusDegraded: reading works with a known problem.
	StatusDegraded = "DEGRADED"
	// StatusBlind: the source cannot be seen, so silence means nothing.
	StatusBlind = "BLIND"
	// StatusNotConfigured: auditing was never set up.
	StatusNotConfigured = "NOT_CONFIGURED"
)

const (
	// staleAfter is how long a report stays believable. A silent agent reports
	// nothing bad, so an old OBSERVING must not read as still observing.
	staleAfter = 5 * time.Minute

	reasonAgentSilent = "AGENT_SILENT"
	reasonNoReports   = "NO_HEALTH_REPORTS"

	capabilityReadAudit = "CAPABILITY_READ_AUDIT"
	supportAvailable    = "SUPPORT_AVAILABLE"
	stateObserving      = "AUDIT_SOURCE_STATE_OBSERVING"
	stateDegraded       = "AUDIT_SOURCE_STATE_DEGRADED"
	stateNotConfigured  = "AUDIT_SOURCE_STATE_NOT_CONFIGURED"
)

// Health is the last report of a source's collector.
type Health struct {
	SourceID       uuid.UUID
	State          string
	ReasonCode     string
	PositionReadAt *time.Time
	LostEvents     int64
	ReportedAt     time.Time
}

// ScanState is the outcome of the latest scan.
type ScanState struct {
	Status     string
	FinishedAt *time.Time
}

// Row is the state of one source.
type Row struct {
	SourceID       uuid.UUID
	SourceKey      string
	Engine         string
	Status         string
	Reason         string
	ReadsAudited   bool
	LastScan       *ScanState
	LastEvent      *time.Time
	PositionRead   *time.Time
	Statements     uint64
	Gaps           uint64
	LostEvents     int64
	ColumnsShare   *float64
	VerifiedShare  *float64
	PrincipalShare *float64
}

// Store reads what coverage is computed from.
type Store interface {
	HealthReports(ctx context.Context, tenantID uuid.UUID) ([]Health, error)
	LatestScans(ctx context.Context, tenantID uuid.UUID) (map[uuid.UUID]ScanState, error)
}

// Service computes coverage.
type Service struct {
	fleet  *fleet.Service
	store  Store
	events audit.Reader
	now    func() time.Time
}

func NewService(fleetService *fleet.Service, store Store, events audit.Reader) *Service {
	return &Service{fleet: fleetService, store: store, events: events, now: time.Now}
}

// Report builds the table for a period.
func (s *Service) Report(ctx context.Context, tenantID uuid.UUID, window time.Duration) ([]Row, error) {
	now := s.now()
	sources, err := s.fleet.ListSources(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	reports, err := s.store.HealthReports(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	scans, err := s.store.LatestScans(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	windows, err := s.events.Windows(ctx, tenantID, now.Add(-window), now)
	if err != nil {
		return nil, err
	}
	rows := make([]Row, 0, len(sources))
	for i := range sources {
		rows = append(rows, buildRow(&sources[i], reports, scans, windows, now))
	}
	return rows, nil
}

func buildRow(source *fleet.Source, reports []Health, scans map[uuid.UUID]ScanState, windows []audit.SourceWindow, now time.Time) Row {
	row := Row{SourceID: source.ID, SourceKey: source.Key, Engine: source.Engine, ReadsAudited: readsAudited(source)}
	row.Status, row.Reason = StatusBlind, reasonNoReports
	if index := slices.IndexFunc(reports, func(h Health) bool { return h.SourceID == source.ID }); index >= 0 {
		health := &reports[index]
		row.Status, row.Reason = classify(health, now)
		row.PositionRead, row.LostEvents = health.PositionReadAt, health.LostEvents
	}
	if scan, found := scans[source.ID]; found {
		row.LastScan = &scan
	}
	if index := slices.IndexFunc(windows, func(w audit.SourceWindow) bool { return w.SourceID == source.ID }); index >= 0 {
		applyWindow(&row, &windows[index])
	}
	return row
}

func readsAudited(source *fleet.Source) bool {
	return slices.ContainsFunc(source.Capabilities, func(c fleet.Capability) bool {
		return c.Capability == capabilityReadAudit && c.Support == supportAvailable
	})
}

func classify(health *Health, now time.Time) (string, string) {
	if now.Sub(health.ReportedAt) > staleAfter {
		return StatusBlind, reasonAgentSilent
	}
	switch health.State {
	case stateObserving:
		return StatusObserving, ""
	case stateDegraded:
		return StatusDegraded, health.ReasonCode
	case stateNotConfigured:
		return StatusNotConfigured, health.ReasonCode
	default:
		return StatusBlind, health.ReasonCode
	}
}

func applyWindow(row *Row, window *audit.SourceWindow) {
	row.Statements, row.Gaps = window.Statements, window.Gaps
	if !window.LastEvent.IsZero() {
		last := window.LastEvent
		row.LastEvent = &last
	}
	row.ColumnsShare = share(window.Resolved, window.Statements)
	row.VerifiedShare = share(window.Verified, window.Statements)
	row.PrincipalShare = share(window.Identified, window.Statements)
}

// share is empty without statements: 0% would claim a measurement that never
// happened.
func share(part, total uint64) *float64 {
	if total == 0 {
		return nil
	}
	value := float64(part) / float64(total)
	return &value
}
