package runtime

import (
	"context"
	"crypto/ecdh"
	"log/slog"
	"net"

	"github.com/google/uuid"

	"dataguard/internal/agent/config"
	"dataguard/internal/agent/sources"
	"dataguard/internal/contract/codes"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/sealing"
)

const (
	maxPort           = 65535
	maxConnections    = 8
	defaultSourcePool = 2
)

var tlsModes = map[agentv1.TLSMode]string{
	agentv1.TLSMode_TLS_MODE_VERIFY_FULL: "verify-full",
	agentv1.TLSMode_TLS_MODE_REQUIRE:     "require",
	agentv1.TLSMode_TLS_MODE_DISABLE:     "disable",
}

// SourceSync applies the center's source list, keeping only what the local
// allowlist permits and what this agent's key opens.
type SourceSync struct {
	Registry  *sources.Registry
	Allowlist *config.Allowlist
	Key       *ecdh.PrivateKey
	TenantID  uuid.UUID
	AgentID   uuid.UUID
	// Resolve defaults to the system resolver.
	Resolve config.Resolver
	Logger  *slog.Logger
}

// ApplySources implements SourceConsumer.
func (s *SourceSync) ApplySources(ctx context.Context, list *agentv1.SourceList) {
	var definitions []sources.Definition
	var refusals []sources.Refusal
	for _, item := range list.GetSources() {
		definition, code := s.resolve(ctx, item)
		if code != "" {
			refusals = append(refusals, sources.Refusal{ID: item.GetSourceId(), Engine: item.GetEngine(), Code: code})
			s.Logger.Warn("source refused", "source_id", item.GetSourceId(), "code", code)
			continue
		}
		definitions = append(definitions, definition)
	}
	if err := s.Registry.Apply(definitions, refusals); err != nil {
		s.Logger.Error("sources not opened", "error", err)
	}
	s.Logger.Info("sources applied", "sources_version", list.GetVersion(), "sources_open", len(definitions), "sources_refused", len(refusals))
}

func (s *SourceSync) resolve(ctx context.Context, item *agentv1.SourceDefinition) (sources.Definition, string) {
	engine, knownEngine := sources.Engines[item.GetEngine()]
	tls, knownTLS := tlsModes[item.GetTls()]
	if _, err := uuid.Parse(item.GetSourceId()); err != nil || !knownEngine || !knownTLS ||
		item.GetPort() == 0 || item.GetPort() > maxPort {
		return sources.Definition{}, codes.InvalidDefinition
	}
	resolve := s.Resolve
	if resolve == nil {
		resolve = net.DefaultResolver.LookupNetIP
	}
	if !s.Allowlist.PermitsHost(ctx, item.GetHost(), resolve) {
		return sources.Definition{}, codes.TargetNotAllowed
	}
	// SQL Server reads its audit through SQL from a path on its own server.
	if item.GetAuditDirectory() != "" && engine != sources.EngineMSSQL &&
		!s.Allowlist.PermitsAuditDirectory(item.GetAuditDirectory()) {
		return sources.Definition{}, codes.AuditDirectoryNotAllowed
	}
	if s.Key == nil {
		return sources.Definition{}, codes.CredentialUnreadable
	}
	port := int(item.GetPort())
	password, err := sealing.Open(s.Key, sealing.Binding{
		TenantID: s.TenantID, AgentID: s.AgentID, Engine: engine, Host: item.GetHost(), Port: port,
		Database: item.GetDatabase(), Username: item.GetUsername(), TLS: tls,
	}, item.GetSealedPassword())
	if err != nil {
		return sources.Definition{}, codes.CredentialUnreadable
	}
	defer clear(password)
	pool := int(item.GetMaxConnections())
	if pool == 0 {
		pool = defaultSourcePool
	}
	return sources.Definition{
		ID: item.GetSourceId(), Name: item.GetName(), Engine: engine, Host: item.GetHost(), Port: port,
		Database: item.GetDatabase(), Username: item.GetUsername(), Password: string(password), TLS: tls,
		MaxConnections: min(pool, maxConnections), AuditDirectory: item.GetAuditDirectory(),
		ProbeOnly: item.GetProbeOnly(),
	}, ""
}
