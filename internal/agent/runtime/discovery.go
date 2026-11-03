package runtime

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	"dataguard/internal/agent/center"
	"dataguard/internal/agent/scanner"
	"dataguard/internal/agent/sources"
	"dataguard/internal/classifier"
	"dataguard/internal/contract/codes"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/retry"
	"dataguard/internal/platform/safeerr"
)

const (
	defaultJobPollInterval = 15 * time.Second
	submitAttempts         = 5
	// One scan at a time keeps the agent's load on production databases bounded.
	jobsPerPoll = 1
)

// scanSettings is swapped as a whole when a new policy arrives.
type scanSettings struct {
	engine *classifier.Engine
	budget *agentv1.ScanBudget
}

// Discovery runs scan jobs assigned by the center.
type Discovery struct {
	client       *center.Client
	registry     *sources.Registry
	logger       *slog.Logger
	pollInterval time.Duration
	settings     atomic.Pointer[scanSettings]
	backoff      retry.Backoff
}

// NewDiscovery creates a job runner with built-in rules until a policy arrives.
func NewDiscovery(client *center.Client, registry *sources.Registry, pollInterval time.Duration, logger *slog.Logger) *Discovery {
	if pollInterval == 0 {
		pollInterval = defaultJobPollInterval
	}
	discovery := &Discovery{
		client: client, registry: registry, logger: logger, pollInterval: pollInterval,
		backoff: retry.Backoff{Base: backoffBase, Max: backoffMax},
	}
	discovery.settings.Store(&scanSettings{engine: classifier.NewEngine(classifier.Custom{})})
	return discovery
}

// ApplyPolicy recompiles detectors. A policy that fails to compile keeps the
// previous rules: scanning with old rules is better than not scanning.
func (d *Discovery) ApplyPolicy(policy *agentv1.Policy) {
	compiled, err := classifier.CompileCustom(policy.GetCustomDetectors())
	if err != nil {
		d.logger.Error("policy detectors rejected", "policy_version", policy.GetVersion())
		return
	}
	d.settings.Store(&scanSettings{engine: classifier.NewEngine(compiled), budget: policy.GetDefaultBudget()})
}

// Run polls for jobs until ctx ends.
func (d *Discovery) Run(ctx context.Context) {
	failures := 0
	for {
		wait := d.pollInterval
		jobs, err := d.client.PullJobs(ctx, jobsPerPoll)
		switch {
		case err != nil && ctx.Err() == nil:
			wait = d.backoff.Delay(failures)
			failures++
			d.logger.Warn("job poll failed", "error", rpcError("pull jobs", err), "backoff", wait.String())
		case err == nil:
			failures = 0
			d.runJobs(ctx, jobs)
			if len(jobs) > 0 {
				// More may be waiting: the interval is for an idle queue, and scans
				// still run one at a time.
				wait = 0
			}
		}
		if !retry.Sleep(ctx, wait) {
			return
		}
	}
}

func (d *Discovery) runJobs(ctx context.Context, jobs []*agentv1.ScanJob) {
	for _, job := range jobs {
		if ctx.Err() != nil {
			return
		}
		d.submit(ctx, d.execute(ctx, job))
	}
}

func (d *Discovery) execute(ctx context.Context, job *agentv1.ScanJob) *agentv1.ScanResult {
	source, release, known := d.registry.Acquire(job.GetSourceId())
	if !known {
		return &agentv1.ScanResult{
			JobId: job.GetJobId(), SourceId: job.GetSourceId(),
			Outcome: agentv1.ScanOutcome_SCAN_OUTCOME_FAILED, FailureCode: codes.UnknownSource,
			StartedAt: timestamppb.Now(), FinishedAt: timestamppb.Now(),
		}
	}
	defer release()
	settings := d.settings.Load()
	if job.GetBudget() == nil {
		job.Budget = settings.budget
	}
	d.logger.Info("scan started", "job_id", job.GetJobId(), "source_id", job.GetSourceId())
	result := scanner.New(settings.engine, d.logger).Scan(ctx, source, job)
	d.logger.Info("scan finished", "job_id", job.GetJobId(), "outcome", result.GetOutcome().String(), "tables", len(result.GetTables()))
	return result
}

// submit retries a transient failure. If it never succeeds the job's lease
// expires and the center schedules it again, so giving up loses nothing.
func (d *Discovery) submit(ctx context.Context, result *agentv1.ScanResult) {
	for attempt := range submitAttempts {
		err := d.client.SubmitScanResult(ctx, result)
		if err == nil {
			return
		}
		if connect.CodeOf(err) == connect.CodeFailedPrecondition {
			d.logger.Warn("scan result refused", "job_id", result.GetJobId(), "code", string(safeerr.CodeInvalid))
			return
		}
		d.logger.Warn("scan result not delivered", "error", rpcError("submit scan", err), "attempt", attempt)
		if !retry.Sleep(ctx, d.backoff.Delay(attempt)) {
			return
		}
	}
}
