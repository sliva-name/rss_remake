// Package api serves the public REST API described by api/openapi. Handlers are
// generated from that schema; this package only adapts them to the core.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"dataguard/internal/contract/codes"
	"dataguard/internal/core/asset"
	"dataguard/internal/core/audit"
	"dataguard/internal/core/coverage"
	"dataguard/internal/core/fleet"
	"dataguard/internal/core/oplog"
	"dataguard/internal/core/policy"
	"dataguard/internal/core/preference"
	"dataguard/internal/core/scan"
	"dataguard/internal/core/tenant"
	"dataguard/internal/gen/restapi"
	"dataguard/internal/platform/safeerr"
	"dataguard/internal/server/telemetry"
)

const maxRequestBytes = 1 << 20

// Services are the use cases the API exposes.
type Services struct {
	Tenants     *tenant.Service
	Fleet       *fleet.Service
	Policies    *policy.Service
	Scans       *scan.Service
	Catalog     asset.Reader
	Events      audit.Reader
	Coverage    *coverage.Service
	Preferences *preference.Service
	Journal     *oplog.Service
}

// Server implements the generated strict interface.
type Server struct {
	tenants     *tenant.Service
	fleet       *fleet.Service
	policies    *policy.Service
	scans       *scan.Service
	catalog     asset.Reader
	events      audit.Reader
	coverage    *coverage.Service
	preferences *preference.Service
	journal     *oplog.Service
	signals     *signalCache
}

// Handler builds the HTTP handler with authentication and authorization.
func Handler(server *Server, authenticator Authenticator, logger *slog.Logger, metrics *telemetry.Server) http.Handler {
	strict := restapi.NewStrictHandlerWithOptions(server, []restapi.StrictMiddlewareFunc{authorize},
		restapi.StrictHTTPServerOptions{
			RequestErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, _ error) {
				writeProblem(w, http.StatusBadRequest, "invalid_request", "request is malformed")
			},
			ResponseErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
				writeError(w, logger, err)
			},
		})
	router := http.NewServeMux()
	routes := restapi.HandlerWithOptions(strict, restapi.StdHTTPServerOptions{
		BaseURL: "/api/v1", BaseRouter: router,
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, _ error) {
			writeProblem(w, http.StatusBadRequest, "invalid_request", "request is malformed")
		},
	})
	return metrics.API(router, limitBody(authenticate(authenticator, routes)))
}

// New creates the REST adapter.
func New(services Services) *Server {
	return &Server{
		tenants: services.Tenants, fleet: services.Fleet, policies: services.Policies,
		scans: services.Scans, catalog: services.Catalog, events: services.Events, coverage: services.Coverage,
		preferences: services.Preferences, journal: services.Journal, signals: &signalCache{},
	}
}

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, logger *slog.Logger, err error) {
	switch {
	case errors.Is(err, errUnauthenticated):
		writeProblem(w, http.StatusUnauthorized, "unauthenticated", err.Error())
	case errors.Is(err, errForbidden), errors.Is(err, errNoTenant):
		writeProblem(w, http.StatusForbidden, "forbidden", err.Error())
	case errors.Is(err, fleet.ErrNotFound), errors.Is(err, scan.ErrNotFound), errors.Is(err, policy.ErrNotFound),
		errors.Is(err, asset.ErrNotFound):
		writeProblem(w, http.StatusNotFound, "not_found", "resource not found")
	case errors.Is(err, tenant.ErrConflict), errors.Is(err, fleet.ErrConflict):
		writeProblem(w, http.StatusConflict, "conflict", err.Error())
	case errors.Is(err, tenant.ErrInvalid), errors.Is(err, fleet.ErrInvalid), errors.Is(err, policy.ErrInvalid),
		errors.Is(err, preference.ErrInvalid), errors.Is(err, errInvalidParameter):
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
	default:
		logger.Error("request failed", "error", err, "code", string(safeerr.CodeOf(err)))
		writeProblem(w, http.StatusInternalServerError, "internal", "internal error")
	}
}

func writeProblem(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(restapi.Problem{Code: code, Message: message})
}

func tenantOf(ctx context.Context) uuid.UUID {
	// The authorize middleware has already rejected callers without a tenant.
	principal, _ := principalFrom(ctx)
	return principal.TenantID
}

func (s *Server) GetCurrentUser(ctx context.Context, _ restapi.GetCurrentUserRequestObject) (restapi.GetCurrentUserResponseObject, error) {
	principal, _ := principalFrom(ctx)
	user := restapi.CurrentUser{Subject: principal.Subject, Roles: principal.Roles, Permissions: permissionsOf(principal)}
	if principal.TenantID != uuid.Nil {
		id := principal.TenantID
		user.TenantId = &id
	}
	return restapi.GetCurrentUser200JSONResponse(user), nil
}

func (s *Server) ListTenants(ctx context.Context, _ restapi.ListTenantsRequestObject) (restapi.ListTenantsResponseObject, error) {
	tenants, err := s.tenants.ListTenants(ctx)
	if err != nil {
		return nil, err
	}
	return restapi.ListTenants200JSONResponse(convertAll(tenants, toTenant)), nil
}

func (s *Server) CreateTenant(ctx context.Context, request restapi.CreateTenantRequestObject) (restapi.CreateTenantResponseObject, error) {
	created, err := s.tenants.CreateTenant(ctx, request.Body.Name)
	if err != nil {
		return nil, err
	}
	return restapi.CreateTenant201JSONResponse(toTenant(created)), nil
}

func (s *Server) ListEnvironments(ctx context.Context, _ restapi.ListEnvironmentsRequestObject) (restapi.ListEnvironmentsResponseObject, error) {
	environments, err := s.tenants.ListEnvironments(ctx, tenantOf(ctx))
	if err != nil {
		return nil, err
	}
	return restapi.ListEnvironments200JSONResponse(convertAll(environments, toEnvironment)), nil
}

func (s *Server) CreateEnvironment(ctx context.Context, request restapi.CreateEnvironmentRequestObject) (restapi.CreateEnvironmentResponseObject, error) {
	created, err := s.tenants.CreateEnvironment(ctx, tenantOf(ctx), request.Body.Name, string(request.Body.Kind))
	if err != nil {
		return nil, err
	}
	return restapi.CreateEnvironment201JSONResponse(toEnvironment(created)), nil
}

func (s *Server) CreateEnrollmentToken(ctx context.Context, request restapi.CreateEnrollmentTokenRequestObject) (restapi.CreateEnrollmentTokenResponseObject, error) {
	token, expiresAt, err := s.fleet.CreateEnrollmentToken(ctx, tenantOf(ctx), request.Body.EnvironmentId)
	if err != nil {
		return nil, err
	}
	return restapi.CreateEnrollmentToken201JSONResponse{Token: token, ExpiresAt: expiresAt}, nil
}

func (s *Server) ListAgents(ctx context.Context, _ restapi.ListAgentsRequestObject) (restapi.ListAgentsResponseObject, error) {
	agents, err := s.fleet.ListAgents(ctx, tenantOf(ctx))
	if err != nil {
		return nil, err
	}
	return restapi.ListAgents200JSONResponse(convertAll(agents, toAgent)), nil
}

func (s *Server) GetAgent(ctx context.Context, request restapi.GetAgentRequestObject) (restapi.GetAgentResponseObject, error) {
	agent, err := s.fleet.GetAgent(ctx, tenantOf(ctx), request.AgentId)
	if err != nil {
		return nil, err
	}
	return restapi.GetAgent200JSONResponse(toAgent(agent)), nil
}

func (s *Server) RevokeAgent(ctx context.Context, request restapi.RevokeAgentRequestObject) (restapi.RevokeAgentResponseObject, error) {
	if err := s.fleet.Revoke(ctx, tenantOf(ctx), request.AgentId); err != nil {
		return nil, err
	}
	return restapi.RevokeAgent204Response{}, nil
}

func (s *Server) ListSources(ctx context.Context, _ restapi.ListSourcesRequestObject) (restapi.ListSourcesResponseObject, error) {
	sources, err := s.fleet.ListSources(ctx, tenantOf(ctx))
	if err != nil {
		return nil, err
	}
	return restapi.ListSources200JSONResponse(convertAll(sources, toSource)), nil
}

func (s *Server) GetSource(ctx context.Context, request restapi.GetSourceRequestObject) (restapi.GetSourceResponseObject, error) {
	source, err := s.fleet.GetSource(ctx, tenantOf(ctx), request.SourceId)
	if err != nil {
		return nil, err
	}
	return restapi.GetSource200JSONResponse(toSource(source)), nil
}

func (s *Server) CreateSource(ctx context.Context, request restapi.CreateSourceRequestObject) (restapi.CreateSourceResponseObject, error) {
	body := request.Body
	draft := sourceDraft(body.Name, string(body.Engine), body.Host, body.Port, body.Database, body.Username,
		string(body.Tls), body.AuditDirectory, body.MaxConnections, body.SealedPassword)
	draft.AgentID = body.AgentId
	draft.Draft = body.Draft != nil && *body.Draft
	created, err := s.fleet.CreateSource(ctx, tenantOf(ctx), draft)
	if err != nil {
		return nil, err
	}
	return restapi.CreateSource201JSONResponse(toSource(created)), nil
}

func (s *Server) ActivateSource(ctx context.Context, request restapi.ActivateSourceRequestObject) (restapi.ActivateSourceResponseObject, error) {
	activated, err := s.fleet.ActivateSource(ctx, tenantOf(ctx), request.SourceId)
	if err != nil {
		return nil, err
	}
	return restapi.ActivateSource200JSONResponse(toSource(activated)), nil
}

func (s *Server) UpdateSource(ctx context.Context, request restapi.UpdateSourceRequestObject) (restapi.UpdateSourceResponseObject, error) {
	body := request.Body
	var sealed []byte
	if body.SealedPassword != nil {
		sealed = *body.SealedPassword
	}
	draft := sourceDraft(body.Name, string(body.Engine), body.Host, body.Port, body.Database, body.Username,
		string(body.Tls), body.AuditDirectory, body.MaxConnections, sealed)
	updated, err := s.fleet.UpdateSource(ctx, tenantOf(ctx), request.SourceId, draft)
	if err != nil {
		return nil, err
	}
	return restapi.UpdateSource200JSONResponse(toSource(updated)), nil
}

func (s *Server) DeleteSource(ctx context.Context, request restapi.DeleteSourceRequestObject) (restapi.DeleteSourceResponseObject, error) {
	if err := s.fleet.DeleteSource(ctx, tenantOf(ctx), request.SourceId); err != nil {
		return nil, err
	}
	return restapi.DeleteSource204Response{}, nil
}

func sourceDraft(name, engine, host string, port int, database, username, tls string, auditDirectory *string, maxConnections *int, sealed []byte) fleet.Source {
	draft := fleet.Source{
		Key: name, Engine: engine, Host: host, Port: port, Database: database, Username: username,
		TLS: tls, SealedPassword: sealed,
	}
	if auditDirectory != nil {
		draft.AuditDirectory = *auditDirectory
	}
	if maxConnections != nil {
		draft.MaxConnections = *maxConnections
	}
	return draft
}

// convertAll never returns nil, so an empty list is encoded as [], not null.
func convertAll[T, R any](items []T, convert func(T) R) []R {
	result := make([]R, 0, len(items))
	for _, item := range items {
		result = append(result, convert(item))
	}
	return result
}

func toTenant(item tenant.Tenant) restapi.Tenant {
	return restapi.Tenant{Id: item.ID, Name: item.Name, CreatedAt: item.CreatedAt}
}

func toEnvironment(item tenant.Environment) restapi.Environment {
	return restapi.Environment{Id: item.ID, Name: item.Name, Kind: restapi.EnvironmentKind(item.Kind), CreatedAt: item.CreatedAt}
}

func toAgent(item fleet.Agent) restapi.Agent {
	agent := restapi.Agent{
		Id: item.ID, EnvironmentId: item.EnvironmentID, Status: restapi.AgentStatus(item.Status),
		Version: item.Version, ContractVersion: int32(item.ContractVersion), CertificateExpires: item.CertificateExpires,
		LastSeenAt: item.LastSeenAt, CreatedAt: item.CreatedAt,
	}
	if len(item.SealingPublicKey) > 0 {
		agent.SealingPublicKey = &item.SealingPublicKey
	}
	if item.RefusedContractVersion != nil {
		agent.ProblemCode = new(codes.ContractUnsupported)
	}
	return agent
}

func toSource(item fleet.Source) restapi.Source {
	capabilities := convertAll(item.Capabilities, func(capability fleet.Capability) restapi.Capability {
		return restapi.Capability{Capability: capability.Capability, Support: capability.Support, ReasonCode: capability.ReasonCode}
	})
	return restapi.Source{
		Id: item.ID, AgentId: item.AgentID, Key: item.Key, Engine: item.Engine,
		Host: item.Host, Port: item.Port, Database: item.Database, Username: item.Username,
		Tls: restapi.TlsMode(item.TLS), AuditDirectory: item.AuditDirectory, MaxConnections: item.MaxConnections,
		StatusCode: item.StatusCode, ProbedAt: item.ProbedAt,
		EngineVersion: item.EngineVersion, Capabilities: capabilities, UpdatedAt: item.UpdatedAt, Draft: item.Draft,
	}
}
