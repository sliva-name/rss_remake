// Package runtime drives the agent's connection to the center. Every step is
// retried with backoff and survives the center being down; only cancellation of
// the context stops the loop.
package runtime

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"connectrpc.com/connect/v2"

	"dataguard/internal/agent/center"
	"dataguard/internal/agent/identity"
	"dataguard/internal/agent/telemetry"
	"dataguard/internal/contract/codes"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/pki"
	"dataguard/internal/platform/retry"
	"dataguard/internal/platform/safeerr"
)

const (
	// A new source or policy reaches the agent within one interval.
	defaultHeartbeatInterval = 10 * time.Second
	// Sources are probed again on this interval, so a database that became
	// reachable or got auditing enabled shows up without a restart.
	probeInterval = 5 * time.Minute
	backoffBase   = time.Second
	backoffMax    = 5 * time.Minute
)

// SourceProber reports what the configured sources can do right now.
type SourceProber interface {
	Probe(ctx context.Context) []*agentv1.SourceReport
}

// HealthReporter fills the operational part of a heartbeat.
type HealthReporter interface {
	Health() (*agentv1.QueueHealth, []*agentv1.AuditSourceHealth)
}

// SourceConsumer receives each newly accepted source list.
type SourceConsumer interface {
	ApplySources(ctx context.Context, list *agentv1.SourceList)
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
	Sources           SourceConsumer
	Policies          PolicyConsumer
	Version           string
	HeartbeatInterval time.Duration
	Logger            *slog.Logger
	// Metrics may be nil.
	Metrics *telemetry.Agent
}

// Control keeps the agent registered and up to date.
type Control struct {
	options Options
	backoff retry.Backoff
	// reportedAt stays zero after a failed report so the next tick retries it,
	// and is reset when the source list changes.
	reportedAt time.Time
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

// tick renews the certificate whatever happened to the other steps: once it
// expires the agent cannot even ask for a new one, and a step that keeps failing
// would otherwise lock the agent out for good.
func (c *Control) tick(ctx context.Context) error {
	return errors.Join(c.synchronize(ctx), c.renewCertificate(ctx))
}

func (c *Control) synchronize(ctx context.Context) error {
	latest, err := c.heartbeat(ctx)
	if err != nil {
		return err
	}
	// A rotated key first: the policy and the list are already signed by it.
	if err := c.refreshPolicyKeys(ctx, latest.GetPolicyKeyEpoch()); err != nil {
		return err
	}
	if err := c.refreshPolicy(ctx, latest.GetLatestPolicyVersion()); err != nil {
		return err
	}
	if err := c.refreshSources(ctx, latest.GetLatestSourcesVersion()); err != nil {
		return err
	}
	return c.reportSources(ctx)
}

func (c *Control) reportSources(ctx context.Context) error {
	if !c.reportedAt.IsZero() && time.Since(c.reportedAt) < probeInterval {
		return nil
	}
	if _, err := c.options.Client.ReportSources(ctx, c.options.Prober.Probe(ctx)); err != nil {
		return rpcError("report sources", err)
	}
	c.reportedAt = time.Now()
	return nil
}

func (c *Control) refreshSources(ctx context.Context, latest uint64) error {
	if latest <= c.options.Identity.SourcesVersion() || c.options.Sources == nil {
		return nil
	}
	response, err := c.options.Client.GetSources(ctx)
	if err != nil {
		return rpcError("get sources", err)
	}
	list, err := c.options.Identity.AcceptSources(response.GetSourceList(), response.GetSignature())
	if err != nil {
		// Like a bad policy: an incident, and the agent keeps the list it trusts.
		reason := rejection(err)
		c.options.Logger.Error("source list rejected", "reason", reason)
		c.options.Metrics.Rejected("sources", reason)
		return nil
	}
	c.options.Sources.ApplySources(ctx, list)
	c.reportedAt = time.Time{}
	return nil
}

func (c *Control) refreshPolicyKeys(ctx context.Context, latest uint32) error {
	if latest <= c.options.Identity.PolicyKeyEpoch() {
		return nil
	}
	chain, err := c.options.Client.GetSigningKeys(ctx)
	if err != nil {
		return rpcError("get signing keys", err)
	}
	epoch, err := c.options.Identity.AcceptPolicyKeys(chain)
	if err != nil {
		// Like a forged policy: the agent keeps the key it trusts and refuses
		// whatever the unendorsed key signs.
		reason := rejection(err)
		c.options.Logger.Error("policy key rejected", "reason", reason)
		c.options.Metrics.Rejected("policy_keys", reason)
		return nil
	}
	c.options.Logger.Info("policy key rotated", "version", epoch)
	return nil
}

func rejection(err error) string {
	switch {
	case errors.Is(err, pki.ErrBadSignature), errors.Is(err, pki.ErrBrokenChain):
		return "bad_signature"
	case errors.Is(err, identity.ErrPolicyRollback), errors.Is(err, identity.ErrSourcesRollback):
		return "rollback"
	default:
		return "invalid"
	}
}

func (c *Control) heartbeat(ctx context.Context) (*agentv1.HeartbeatResponse, error) {
	request := &agentv1.HeartbeatRequest{
		AgentVersion: c.options.Version, PolicyKeyEpoch: c.options.Identity.PolicyKeyEpoch(),
		AppliedPolicyVersion: c.options.Identity.PolicyVersion(), AppliedSourcesVersion: c.options.Identity.SourcesVersion(),
	}
	if c.options.Health != nil {
		request.Queue, request.AuditSources = c.options.Health.Health()
	}
	response, err := c.options.Client.Heartbeat(ctx, request)
	if connect.CodeOf(err) == connect.CodeFailedPrecondition {
		// The center does not, or does not yet, speak this agent's contract. Events
		// wait in the queue until the agent or the center is upgraded.
		c.options.Logger.Error("center refused the agent version", "code", codes.ContractUnsupported, "version", c.options.Version)
	}
	if err != nil {
		return nil, rpcError("heartbeat", err)
	}
	return response, nil
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
		reason := rejection(err)
		c.options.Logger.Error("policy rejected", "reason", reason)
		c.options.Metrics.Rejected("policy", reason)
		return nil
	}
	if c.options.Policies != nil {
		c.options.Policies.ApplyPolicy(policy)
	}
	c.options.Logger.Info("policy applied", "policy_version", policy.GetVersion())
	return nil
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
