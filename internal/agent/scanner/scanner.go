// Package scanner runs discovery on a source: it reads the catalog, feeds a
// bounded sample through the classifier and reports aggregates. Values exist
// only for the duration of one Observe call.
package scanner

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/axiomhq/hyperloglog"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/types/known/timestamppb"

	"dataguard/internal/classifier"
	"dataguard/internal/connector"
	"dataguard/internal/connector/sqlsource"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/safeerr"
)

const (
	defaultMaxDuration      = 10 * time.Minute
	defaultMaxRowsPerTable  = 10_000
	defaultMaxBytesPerTable = 64 << 20
	defaultMaxConnections   = 2
	defaultRowsPerSecond    = 5_000

	reasonBudgetExhausted = "BUDGET_EXHAUSTED"
	reasonReadFailed      = "READ_FAILED"
	reasonCanceled        = "CANCELED"
)

// EffectiveBudget fills unset limits with conservative defaults, because an
// empty budget must never mean an unbounded scan of a production database.
func EffectiveBudget(budget *agentv1.ScanBudget) *agentv1.ScanBudget {
	effective := &agentv1.ScanBudget{
		MaxDurationSeconds: uint32(defaultMaxDuration.Seconds()),
		MaxRowsPerTable:    defaultMaxRowsPerTable,
		MaxBytesPerTable:   defaultMaxBytesPerTable,
		MaxConnections:     defaultMaxConnections,
		MaxRowsPerSecond:   defaultRowsPerSecond,
	}
	if value := budget.GetMaxDurationSeconds(); value > 0 {
		effective.MaxDurationSeconds = value
	}
	if value := budget.GetMaxRowsPerTable(); value > 0 {
		effective.MaxRowsPerTable = value
	}
	if value := budget.GetMaxBytesPerTable(); value > 0 {
		effective.MaxBytesPerTable = value
	}
	if value := budget.GetMaxConnections(); value > 0 {
		effective.MaxConnections = value
	}
	if value := budget.GetMaxRowsPerSecond(); value > 0 {
		effective.MaxRowsPerSecond = value
	}
	return effective
}

// Scanner runs jobs with one classifier engine.
type Scanner struct {
	engine *classifier.Engine
	logger *slog.Logger
}

func New(engine *classifier.Engine, logger *slog.Logger) *Scanner {
	return &Scanner{engine: engine, logger: logger}
}

// Scan executes job against source. It always returns a result: a failed scan
// must reach the center as such, or the absence of findings would read as
// "nothing sensitive here".
func (s *Scanner) Scan(ctx context.Context, source connector.Scannable, job *agentv1.ScanJob) *agentv1.ScanResult {
	budget := EffectiveBudget(job.GetBudget())
	ctx, cancel := context.WithTimeout(ctx, time.Duration(budget.GetMaxDurationSeconds())*time.Second)
	defer cancel()

	result := &agentv1.ScanResult{
		JobId: job.GetJobId(), SourceId: job.GetSourceId(), StartedAt: timestamppb.Now(),
	}
	tables, err := source.Tables(ctx)
	if err != nil {
		result.Outcome = outcomeOfFailure(err)
		result.FailureCode = string(safeerr.CodeOf(err))
		result.FinishedAt = timestamppb.Now()
		return result
	}
	s.scanTables(ctx, source, tables, budget, result)
	result.Outcome = outcomeOf(result)
	result.FinishedAt = timestamppb.Now()
	return result
}

func outcomeOfFailure(err error) agentv1.ScanOutcome {
	if safeerr.CodeOf(err) == safeerr.CodeCanceled {
		return agentv1.ScanOutcome_SCAN_OUTCOME_CANCELLED
	}
	return agentv1.ScanOutcome_SCAN_OUTCOME_FAILED
}

func outcomeOf(result *agentv1.ScanResult) agentv1.ScanOutcome {
	if len(result.GetSkippedTables()) > 0 {
		return agentv1.ScanOutcome_SCAN_OUTCOME_PARTIAL
	}
	return agentv1.ScanOutcome_SCAN_OUTCOME_COMPLETED
}

func (s *Scanner) scanTables(ctx context.Context, source connector.Scannable, tables []connector.Table, budget *agentv1.ScanBudget, result *agentv1.ScanResult) {
	limits := connector.Limits{
		MaxRows:  budget.GetMaxRowsPerTable(),
		MaxBytes: budget.GetMaxBytesPerTable(),
		Limiter:  rate.NewLimiter(rate.Limit(budget.GetMaxRowsPerSecond()), int(budget.GetMaxRowsPerSecond())),
	}
	var collected sync.Mutex
	group := errgroup.Group{}
	group.SetLimit(int(budget.GetMaxConnections()))
	for i := range tables {
		table := &tables[i]
		result.Tables = append(result.Tables, snapshot(table))
		group.Go(func() error {
			findings, skipped := s.scanTable(ctx, source, table, limits)
			collected.Lock()
			defer collected.Unlock()
			result.Classifications = append(result.Classifications, findings...)
			if skipped != nil {
				result.SkippedTables = append(result.SkippedTables, skipped)
			}
			return nil
		})
	}
	// Workers report through result and never return an error.
	_ = group.Wait()
}

func snapshot(table *connector.Table) *agentv1.TableSnapshot {
	columns := make([]*agentv1.ColumnSnapshot, 0, len(table.Columns))
	for _, column := range table.Columns {
		columns = append(columns, &agentv1.ColumnSnapshot{
			Name: column.Name, NativeType: column.NativeType, Ordinal: column.Ordinal, Nullable: column.Nullable,
		})
	}
	return &agentv1.TableSnapshot{Path: tablePath(table), Kind: table.Kind, Columns: columns}
}

func tablePath(table *connector.Table) *agentv1.TablePath {
	return &agentv1.TablePath{Database: table.Database, Schema: table.Schema, Table: table.Name}
}

// columnProfile is the state kept per column during a read.
type columnProfile struct {
	column   connector.Column
	evidence *classifier.Column
	unique   *hyperloglog.Sketch
	nonNull  uint64
}

func (s *Scanner) scanTable(ctx context.Context, source connector.Sampler, table *connector.Table, limits connector.Limits) ([]*agentv1.ColumnClassification, *agentv1.SkippedTable) {
	if ctx.Err() != nil {
		return s.metadataOnly(table, table.Columns), skip(table, reasonForContext(ctx))
	}
	sampled, unsampled := splitColumns(table)
	findings := s.metadataOnly(table, unsampled)
	if len(sampled) == 0 || table.Kind != agentv1.TableKind_TABLE_KIND_TABLE {
		return append(findings, s.metadataOnly(table, sampled)...), nil
	}

	profiles := make([]*columnProfile, len(sampled))
	selected := make([]connector.Column, len(sampled))
	for i, column := range sampled {
		selected[i] = column
		profiles[i] = &columnProfile{
			column:   column,
			evidence: s.engine.NewColumn(columnContext(table, column)),
			unique:   hyperloglog.New14(),
		}
	}
	stats, err := source.Sample(ctx, *table, selected, limits, func(index int, value []byte) {
		profile := profiles[index]
		profile.nonNull++
		profile.evidence.Observe(value)
		profile.unique.Insert(value)
	})
	if err != nil {
		s.logger.Warn("table read failed", "error", err)
		return append(findings, s.collect(table, profiles, stats)...), skip(table, reasonForError(ctx, err))
	}
	return append(findings, s.collect(table, profiles, stats)...), truncated(table, stats)
}

func truncated(table *connector.Table, stats connector.SampleStats) *agentv1.SkippedTable {
	if stats.Truncated {
		return skip(table, reasonBudgetExhausted)
	}
	return nil
}

func splitColumns(table *connector.Table) (sampled, unsampled []connector.Column) {
	for _, column := range table.Columns {
		if sqlsource.ValueBearing(column.NativeType) {
			sampled = append(sampled, column)
		} else {
			unsampled = append(unsampled, column)
		}
	}
	return sampled, unsampled
}

func columnContext(table *connector.Table, column connector.Column) classifier.ColumnContext {
	return classifier.ColumnContext{
		Schema: table.Schema, Table: table.Name, Column: column.Name,
		NativeType: column.NativeType, Comment: column.Comment,
	}
}

func (s *Scanner) collect(table *connector.Table, profiles []*columnProfile, stats connector.SampleStats) []*agentv1.ColumnClassification {
	var classifications []*agentv1.ColumnClassification
	for _, profile := range profiles {
		for _, finding := range s.engine.Findings(profile.evidence) {
			classifications = append(classifications, &agentv1.ColumnClassification{
				Column:     &agentv1.ColumnPath{Table: tablePath(table), Column: profile.column.Name},
				CategoryId: finding.Category,
				Confidence: finding.Confidence,
				Evidence:   finding.Evidence,
				Profile: &agentv1.ColumnProfile{
					RowsInspected:  stats.Rows,
					RowsNonNull:    profile.nonNull,
					RowsMatched:    finding.Matched,
					UniqueEstimate: profile.unique.Estimate(),
					SamplingMethod: stats.Method,
				},
			})
		}
	}
	return classifications
}

func (s *Scanner) metadataOnly(table *connector.Table, columns []connector.Column) []*agentv1.ColumnClassification {
	var classifications []*agentv1.ColumnClassification
	for _, column := range columns {
		for _, finding := range s.engine.Findings(s.engine.NewColumn(columnContext(table, column))) {
			classifications = append(classifications, &agentv1.ColumnClassification{
				Column:     &agentv1.ColumnPath{Table: tablePath(table), Column: column.Name},
				CategoryId: finding.Category,
				Confidence: finding.Confidence,
				Evidence:   finding.Evidence,
				Profile:    &agentv1.ColumnProfile{SamplingMethod: agentv1.SamplingMethod_SAMPLING_METHOD_METADATA_ONLY},
			})
		}
	}
	return classifications
}

func skip(table *connector.Table, reason string) *agentv1.SkippedTable {
	return &agentv1.SkippedTable{Table: tablePath(table), ReasonCode: reason}
}

func reasonForContext(ctx context.Context) string {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return reasonBudgetExhausted
	}
	return reasonCanceled
}

func reasonForError(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return reasonForContext(ctx)
	}
	if safeerr.CodeOf(err) == safeerr.CodeTimeout {
		return reasonBudgetExhausted
	}
	return reasonReadFailed
}
