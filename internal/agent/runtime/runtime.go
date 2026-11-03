// Package runtime drives the agent's connection to the center. Every step is
// retried with backoff and survives the center being down; only cancellation of
// the context stops the loop.
package runtime

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect"

	"dataguard/internal/agent/center"
	"dataguard/internal/agent/identity"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/pki"
	"dataguard/internal/platform/retry"
	"dataguard/internal/platform/safeerr"
)

const (
	defaultHeartbeatInterval = 30 * time.Second
	backoffBase              = time.Second
	backoffMax               = 5 * time.Minute
)

// SourceProber reports what the configured sources can do right now.
type SourceProber interface {
	Probe(ctx context.Context) []*agentv1.SourceReport
}

// HealthReporter fills the operational part of a heartbeat.
type HealthReporter interface {
	Health() (*agentv1.QueueHealth, []*agentv1.AuditSourceHealth)
}

// SourceAssignments receives the ids the center gave to local source keys.
type SourceAssignments interface {
	Assign(assignments []*agentv1.SourceAssignment)
}

// PolicyConsumer receives each newly accepted policy.
type PolicyConsumer interface {
	ApplyPolicy(policy *agentv1.Policy)
}

// Options configures the control loop.
type Options struct {
	Client            *center.Client
	Identity          *identity.Store
	Prober            SourceProber
	Health            HealthReporter
	Assignments       SourceAssignments
	Policies          PolicyConsumer
	Version           string
	HeartbeatInterval time.Duration
	Logger            *slog.Logger
}

// Control keeps the agent registered and up to date.
type Control struct {
	options Options
	backoff retry.Backoff
	// reported stays false after a failed report so the next tick retries it.
	reported bool
}

// NewControl builds the control loop.
func NewControl(options Options) *Control {
	if options.HeartbeatInterval == 0 {
		options.HeartbeatInterval = defaultHeartbeatInterval
	}
	return &Control{options: options, backoff: retry.Backoff{Base: backoffBase, Max: backoffMax}}
}

// Run blocks until ctx ends.
func (c *Control) Run(ctx context.Context) {
	failures := 0
	for {
		err := c.tick(ctx)
		wait := c.options.HeartbeatInterval
		if err != nil && ctx.Err() == nil {
			wait = c.backoff.Delay(failures)
			failures++
			c.options.Logger.Warn("center unreachable", "error", err, "attempt", failures, "backoff", wait.String())
		} else {
			failures = 0
		}
		if !retry.Sleep(ctx, wait) {
			return
		}
	}
}

func (c *Control) tick(ctx context.Context) error {
	if err := c.reportSources(ctx); err != nil {
		return err
	}
	latest, err := c.heartbeat(ctx)
	if err != nil {
		return err
	}
	if err := c.refreshPolicy(ctx, latest); err != nil {
		return err
	}
	return c.renewCertificate(ctx)
}

func (c *Control) reportSources(ctx context.Context) error {
	if c.reported {
		return nil
	}
	response, err := c.options.Client.ReportSources(ctx, c.options.Prober.Probe(ctx))
	if err != nil {
		return rpcError("report sources", err)
	}
	if c.options.Assignments != nil {
		c.options.Assignments.Assign(response.GetAssignments())
	}
	c.reported = true
	return nil
}

func (c *Control) heartbeat(ctx context.Context) (uint64, error) {
	request := &agentv1.HeartbeatRequest{AgentVersion: c.options.Version}
	if c.options.Health != nil {
		request.Queue, request.AuditSources = c.options.Health.Health()
	}
	response, err := c.options.Client.Heartbeat(ctx, request)
	if err != nil {
		return 0, rpcError("heartbeat", err)
	}
	return response.GetLatestPolicyVersion(), nil
}

func (c *Control) refreshPolicy(ctx context.Context, latest uint64) error {
	if latest <= c.options.Identity.PolicyVersion() {
		return nil
	}
	response, err := c.options.Client.GetPolicy(ctx)
	if err != nil {
		return rpcError("get policy", err)
	}
	policy, err := c.options.Identity.AcceptPolicy(response.GetPolicy(), response.GetSignature())
	if err != nil {
		// A forged or rolled-back policy is an incident, not a retryable failure:
		// the agent keeps working on the policy it already trusts.
		c.options.Logger.Error("policy rejected", "reason", policyRejection(err))
		return nil
	}
	if c.options.Policies != nil {
		c.options.Policies.ApplyPolicy(policy)
	}
	c.options.Logger.Info("policy applied", "policy_version", policy.GetVersion())
	return nil
}

func policyRejection(err error) string {
	switch {
	case errors.Is(err, pki.ErrBadSignature):
		return "bad signature"
	case errors.Is(err, identity.ErrPolicyRollback):
		return "rollback"
	default:
		return "invalid"
	}
}

func (c *Control) renewCertificate(ctx context.Context) error {
	due, err := c.options.Identity.RenewalDue(time.Now())
	if err != nil {
		return safeerr.New("check certificate", safeerr.CodeInternal, err)
	}
	if !due {
		return nil
	}
	csr, key, err := pki.NewCSR()
	if err != nil {
		return safeerr.New("create certificate request", safeerr.CodeInternal, err)
	}
	certificate, err := c.options.Client.RenewCertificate(ctx, csr)
	if err != nil {
		return rpcError("renew certificate", err)
	}
	if err := c.options.Identity.ReplaceCertificate(key, certificate); err != nil {
		return safeerr.New("store certificate", safeerr.CodeInternal, err)
	}
	c.options.Logger.Info("certificate renewed")
	return nil
}

func rpcError(op string, err error) error {
	code := safeerr.CodeUnavailable
	switch connect.CodeOf(err) {
	case connect.CodePermissionDenied, connect.CodeUnauthenticated:
		code = safeerr.CodeUnauthorized
	case connect.CodeInvalidArgument, connect.CodeFailedPrecondition:
		code = safeerr.CodeInvalid
	default:
	}
	return safeerr.New(op, code, err)
}
