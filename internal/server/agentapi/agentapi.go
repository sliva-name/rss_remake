// Package agentapi serves the agent-facing RPC. An agent is an untrusted
// client: its identity comes from the verified certificate, and every message
// is re-validated against the closed contract.
package agentapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"dataguard/internal/contract/egress"
	"dataguard/internal/core/audit"
	"dataguard/internal/core/coverage"
	"dataguard/internal/core/fleet"
	"dataguard/internal/core/policy"
	"dataguard/internal/core/scan"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/gen/dataguard/agent/v1/agentv1connect"
	"dataguard/internal/platform/pki"
	"dataguard/internal/platform/safeerr"
	"dataguard/internal/server/telemetry"
)

// CurrentSchemaVersion is the envelope version this server understands.
const CurrentSchemaVersion = 1

const (
	maxMessageBytes = 16 << 20
	maxLeasedJobs   = 4
)

type identityKey struct{}

func identityFrom(ctx context.Context) (pki.Identity, bool) {
	identity, ok := ctx.Value(identityKey{}).(pki.Identity)
	return identity, ok
}

// withCertificateIdentity moves the verified peer identity into the context.
// TLS has already validated the chain; this only reads who it was issued to.
func withCertificateIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil && len(r.TLS.VerifiedChains) > 0 {
			if identity, err := pki.IdentityOf(r.TLS.VerifiedChains[0][0]); err == nil {
				r = r.WithContext(context.WithValue(r.Context(), identityKey{}, identity))
			}
		}
		next.ServeHTTP(w, r)
	})
}

type enveloped interface {
	GetEnvelope() *agentv1.Envelope
}

// authorizeInterceptor is the single gate for AgentService. Handlers can rely
// on identityFrom returning an active agent whose envelope matches its
// certificate. The certificate and the agent state are checked before the
// request is read, the message as it is read.
func authorizeInterceptor(service *fleet.Service, logger *slog.Logger) connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			identity, ok := identityFrom(ctx)
			if !ok {
				return connect.NewError(connect.CodeUnauthenticated, "client certificate required")
			}
			if err := checkActive(ctx, service, identity, logger); err != nil {
				return err
			}
			return next(ctx, spec, checkedStream{ServerStream: stream, identity: identity})
		}
	}
}

type checkedStream struct {
	connect.ServerStream
	identity pki.Identity
}

func (s checkedStream) Receive(message any) error {
	if err := s.ServerStream.Receive(message); err != nil {
		return err
	}
	return checkMessage(message, s.identity)
}

func checkActive(ctx context.Context, service *fleet.Service, identity pki.Identity, logger *slog.Logger) error {
	err := service.Authorize(ctx, identity.TenantID, identity.AgentID)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fleet.ErrNotActive), errors.Is(err, fleet.ErrNotFound):
		return connect.NewError(connect.CodePermissionDenied, "agent is not active")
	default:
		logger.Error("authorize agent", "error", err, "agent_id", identity.AgentID.String())
		return connect.NewError(connect.CodeUnavailable, "authorization unavailable")
	}
}

func checkMessage(message any, identity pki.Identity) error {
	typed, ok := message.(proto.Message)
	if !ok {
		return connect.NewError(connect.CodeInvalidArgument, "unexpected message")
	}
	if err := egress.Check(typed); err != nil {
		return connect.NewError(connect.CodeInvalidArgument, err.Error()).WithCause(err)
	}
	withEnvelope, ok := message.(enveloped)
	if !ok {
		return connect.NewError(connect.CodeInvalidArgument, "message has no envelope")
	}
	return checkEnvelope(withEnvelope.GetEnvelope(), identity)
}

func checkEnvelope(envelope *agentv1.Envelope, identity pki.Identity) error {
	if envelope.GetSchemaVersion() != CurrentSchemaVersion {
		return connect.NewError(connect.CodeFailedPrecondition, "unsupported schema version")
	}
	if envelope.GetTenantId() != identity.TenantID.String() || envelope.GetAgentId() != identity.AgentID.String() {
		return connect.NewError(connect.CodePermissionDenied, "envelope does not match certificate")
	}
	return nil
}

// HealthStore records what collectors report.
type HealthStore interface {
	SaveHealth(ctx context.Context, tenantID, agentID uuid.UUID, reports []coverage.Health) error
}

// Dependencies are the services the agent API delegates to.
type Dependencies struct {
	Fleet           *fleet.Service
	Policies        *policy.Service
	Scans           *scan.Service
	Audit           *audit.Service
	Health          HealthStore
	CACertificate   []byte
	PolicyPublicKey []byte
	Logger          *slog.Logger
	// Metrics may be nil.
	Metrics *telemetry.Server
}

// Handler mounts enrollment and agent RPC. Enrollment stays outside the
// certificate gate because a new agent has no certificate yet.
func Handler(dependencies Dependencies) http.Handler {
	mux := http.NewServeMux()
	limit := connecthttp.WithReadMaxBytes(maxMessageBytes)

	enrollment := connect.NewServer(dependencies.Metrics.AgentInterceptor())
	agentv1connect.RegisterEnrollmentServiceHandler(enrollment, &enrollmentHandler{dependencies: dependencies})
	connecthttp.Mount(mux, enrollment, limit)

	agents := connect.NewServer(dependencies.Metrics.AgentInterceptor(), authorizeInterceptor(dependencies.Fleet, dependencies.Logger))
	agentv1connect.RegisterAgentServiceHandler(agents, &agentHandler{dependencies: dependencies})
	connecthttp.Mount(mux, agents, limit)

	return withCertificateIdentity(mux)
}

type enrollmentHandler struct {
	dependencies Dependencies
}

func (h *enrollmentHandler) Enroll(ctx context.Context, request *agentv1.EnrollRequest) (*agentv1.EnrollResponse, error) {
	if err := egress.Check(request); err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, err.Error()).WithCause(err)
	}
	enrollment, err := h.dependencies.Fleet.Enroll(ctx, request.GetEnrollmentToken(), request.GetCsrPem(),
		request.GetSealingPublicKey(), request.GetAgentVersion())
	if err != nil {
		return nil, h.mapError(err)
	}
	return &agentv1.EnrollResponse{
		TenantId:         enrollment.TenantID.String(),
		AgentId:          enrollment.AgentID.String(),
		CertificatePem:   enrollment.CertificatePEM,
		CaCertificatePem: h.dependencies.CACertificate,
		PolicyPublicKey:  h.dependencies.PolicyPublicKey,
	}, nil
}

func (h *enrollmentHandler) mapError(err error) error {
	switch {
	case errors.Is(err, fleet.ErrInvalidToken):
		return connect.NewError(connect.CodeUnauthenticated, fleet.ErrInvalidToken.Error())
	case errors.Is(err, fleet.ErrInvalid):
		return connect.NewError(connect.CodeInvalidArgument, "certificate request or sealing key rejected")
	default:
		h.dependencies.Logger.Error("enroll agent", "error", err, "code", string(safeerr.CodeOf(err)))
		return connect.NewError(connect.CodeInternal, "enrollment failed")
	}
}

type agentHandler struct {
	agentv1connect.UnimplementedAgentServiceHandler
	dependencies Dependencies
}

func (h *agentHandler) Heartbeat(ctx context.Context, request *agentv1.HeartbeatRequest) (*agentv1.HeartbeatResponse, error) {
	identity, _ := identityFrom(ctx)
	sourcesVersion, err := h.dependencies.Fleet.Heartbeat(ctx, identity.TenantID, identity.AgentID, request.GetAgentVersion())
	if err != nil {
		return nil, h.internal("heartbeat", err)
	}
	if err := h.dependencies.Health.SaveHealth(ctx, identity.TenantID, identity.AgentID, healthReports(request.GetAuditSources())); err != nil {
		return nil, h.internal("save audit health", err)
	}
	latest, err := h.dependencies.Policies.Latest(ctx, identity.TenantID)
	if err != nil && !errors.Is(err, policy.ErrNotFound) {
		return nil, h.internal("read policy", err)
	}
	return &agentv1.HeartbeatResponse{LatestPolicyVersion: latest.Version, LatestSourcesVersion: sourcesVersion}, nil
}

func healthReports(sources []*agentv1.AuditSourceHealth) []coverage.Health {
	reports := make([]coverage.Health, 0, len(sources))
	now := time.Now().UTC()
	for _, source := range sources {
		sourceID, err := uuid.Parse(source.GetSourceId())
		if err != nil {
			continue
		}
		report := coverage.Health{
			SourceID: sourceID, State: source.GetState().String(), ReasonCode: source.GetReasonCode(),
			LostEvents: int64(source.GetLostEventsTotal()), ReportedAt: now,
		}
		if at := source.GetPositionReadAt(); at != nil {
			position := at.AsTime()
			report.PositionReadAt = &position
		}
		reports = append(reports, report)
	}
	return reports
}

func (h *agentHandler) SubmitEvents(ctx context.Context, request *agentv1.SubmitEventsRequest) (*agentv1.SubmitEventsResponse, error) {
	identity, _ := identityFrom(ctx)
	accepted, err := h.dependencies.Audit.Ingest(ctx, identity.TenantID, identity.AgentID, request.GetEvents())
	if errors.Is(err, audit.ErrForeignSource) {
		return nil, connect.NewError(connect.CodePermissionDenied, audit.ErrForeignSource.Error())
	}
	if err != nil {
		h.dependencies.Logger.Error("ingest events", "error", err, "agent_id", identity.AgentID.String())
		return nil, connect.NewError(connect.CodeUnavailable, "events not stored")
	}
	return &agentv1.SubmitEventsResponse{AcceptedEventIds: accepted}, nil
}

func (h *agentHandler) ReportSources(ctx context.Context, request *agentv1.ReportSourcesRequest) (*agentv1.ReportSourcesResponse, error) {
	identity, _ := identityFrom(ctx)
	probes := make([]fleet.Probe, 0, len(request.GetSources()))
	for _, report := range request.GetSources() {
		sourceID, err := uuid.Parse(report.GetSourceId())
		if err != nil {
			continue
		}
		probes = append(probes, toProbe(sourceID, report))
	}
	if err := h.dependencies.Fleet.RecordProbes(ctx, identity.TenantID, identity.AgentID, probes); err != nil {
		return nil, h.internal("report sources", err)
	}
	return &agentv1.ReportSourcesResponse{}, nil
}

func toProbe(sourceID uuid.UUID, report *agentv1.SourceReport) fleet.Probe {
	capabilities := make([]fleet.Capability, 0, len(report.GetCapabilities()))
	for _, status := range report.GetCapabilities() {
		capabilities = append(capabilities, fleet.Capability{
			Capability: status.GetCapability().String(),
			Support:    status.GetSupport().String(),
			ReasonCode: status.GetReasonCode(),
		})
	}
	return fleet.Probe{
		SourceID: sourceID, EngineVersion: report.GetEngineVersion(),
		StatusCode: report.GetStatusCode(), Capabilities: capabilities,
	}
}

func (h *agentHandler) GetSources(ctx context.Context, _ *agentv1.GetSourcesRequest) (*agentv1.GetSourcesResponse, error) {
	identity, _ := identityFrom(ctx)
	signed, err := h.dependencies.Fleet.SourceList(ctx, identity.TenantID, identity.AgentID)
	if err != nil {
		return nil, h.internal("source list", err)
	}
	return &agentv1.GetSourcesResponse{SourceList: signed.Payload, Signature: signed.Signature}, nil
}

func (h *agentHandler) RenewCertificate(ctx context.Context, request *agentv1.RenewCertificateRequest) (*agentv1.RenewCertificateResponse, error) {
	identity, _ := identityFrom(ctx)
	certificate, err := h.dependencies.Fleet.RenewCertificate(ctx, identity.TenantID, identity.AgentID, request.GetCsrPem())
	if errors.Is(err, fleet.ErrInvalid) {
		return nil, connect.NewError(connect.CodeInvalidArgument, "certificate request rejected")
	}
	if err != nil {
		return nil, h.internal("renew certificate", err)
	}
	return &agentv1.RenewCertificateResponse{CertificatePem: certificate}, nil
}

func (h *agentHandler) GetPolicy(ctx context.Context, _ *agentv1.GetPolicyRequest) (*agentv1.GetPolicyResponse, error) {
	identity, _ := identityFrom(ctx)
	signed, err := h.dependencies.Policies.Latest(ctx, identity.TenantID)
	if errors.Is(err, policy.ErrNotFound) {
		return nil, connect.NewError(connect.CodeNotFound, "no policy published")
	}
	if err != nil {
		return nil, h.internal("read policy", err)
	}
	return &agentv1.GetPolicyResponse{Policy: signed.Payload, Signature: signed.Signature}, nil
}

func (h *agentHandler) PullJobs(ctx context.Context, request *agentv1.PullJobsRequest) (*agentv1.PullJobsResponse, error) {
	identity, _ := identityFrom(ctx)
	maxJobs := min(int(request.GetMaxJobs()), maxLeasedJobs)
	jobs, err := h.dependencies.Scans.Lease(ctx, identity.TenantID, identity.AgentID, maxJobs)
	if err != nil {
		return nil, h.internal("lease jobs", err)
	}
	response := &agentv1.PullJobsResponse{}
	for _, job := range jobs {
		response.Jobs = append(response.Jobs, &agentv1.ScanJob{JobId: job.ID.String(), SourceId: job.SourceID.String()})
	}
	return response, nil
}

func (h *agentHandler) SubmitScanResult(ctx context.Context, request *agentv1.SubmitScanResultRequest) (*agentv1.SubmitScanResultResponse, error) {
	identity, _ := identityFrom(ctx)
	err := h.dependencies.Scans.Complete(ctx, identity.TenantID, identity.AgentID, request.GetResult())
	if errors.Is(err, scan.ErrStale) {
		return nil, connect.NewError(connect.CodeFailedPrecondition, scan.ErrStale.Error())
	}
	if err != nil {
		return nil, h.internal("complete scan", err)
	}
	return &agentv1.SubmitScanResultResponse{}, nil
}

func (h *agentHandler) internal(op string, err error) error {
	h.dependencies.Logger.Error(op, "error", err, "code", string(safeerr.CodeOf(err)))
	return connect.NewError(connect.CodeInternal, "request failed")
}

// Issuer adapts the certificate authority to the core port.
type Issuer struct {
	Authority *pki.Authority
}

func (i Issuer) Issue(csrPEM []byte, tenantID, agentID uuid.UUID) ([]byte, time.Time, error) {
	return i.Authority.IssueAgentCertificate(csrPEM, pki.Identity{TenantID: tenantID, AgentID: agentID})
}
