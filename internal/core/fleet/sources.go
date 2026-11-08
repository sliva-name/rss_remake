package fleet

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/pki"
)

const (
	defaultMaxConnections = 2
	maxConnectionsLimit   = 8
	maxNameRunes          = 128
	maxHostLength         = 253
	maxDirectoryRunes     = 512
	maxPort               = 65535
	// A version-1 sealed password: version byte, P-256 point, nonce, GCM tag.
	minSealedPassword = 1 + 65 + 12 + 16
	maxSealedPassword = minSealedPassword + 1024
	sealedVersion     = 1
	uncompressedPoint = 4
)

var (
	sourceNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	hostPattern       = regexp.MustCompile(`^[A-Za-z0-9._:-]+$`)
)

// Engines maps the names used in the API and in sealed-password bindings to
// the contract enum names stored with the source.
var Engines = map[string]string{
	"postgresql": "ENGINE_POSTGRESQL",
	"mysql":      "ENGINE_MYSQL",
	"mariadb":    "ENGINE_MARIADB",
	"mssql":      "ENGINE_MSSQL",
}

var tlsModes = map[string]agentv1.TLSMode{
	"verify-full": agentv1.TLSMode_TLS_MODE_VERIFY_FULL,
	"require":     agentv1.TLSMode_TLS_MODE_REQUIRE,
	"disable":     agentv1.TLSMode_TLS_MODE_DISABLE,
}

// SignedSources is an agent's source list as it is delivered.
type SignedSources struct {
	Version   uint64
	Payload   []byte
	Signature []byte
}

// CreateSource defines a source served by an active agent that can open
// sealed passwords. Engine arrives as an API name such as postgresql.
func (s *Service) CreateSource(ctx context.Context, tenantID uuid.UUID, source Source) (Source, error) {
	engine, ok := Engines[source.Engine]
	if !ok {
		return Source{}, fmt.Errorf("%w: unknown engine", ErrInvalid)
	}
	source.Engine = engine
	if err := validateSource(&source); err != nil {
		return Source{}, err
	}
	if len(source.SealedPassword) == 0 {
		return Source{}, fmt.Errorf("%w: password is required", ErrInvalid)
	}
	agent, err := s.repository.GetAgent(ctx, tenantID, source.AgentID)
	if err != nil {
		return Source{}, err
	}
	if agent.Status != StatusActive {
		return Source{}, fmt.Errorf("%w: agent is not active", ErrInvalid)
	}
	if len(agent.SealingPublicKey) == 0 {
		return Source{}, fmt.Errorf("%w: agent predates managed sources and must be enrolled again", ErrInvalid)
	}
	source.ID = uuid.Must(uuid.NewV7())
	source.TenantID = tenantID
	if err := s.repository.CreateSource(ctx, source); err != nil {
		return Source{}, err
	}
	return source, nil
}

// UpdateSource changes a source. The agent and the engine stay: events already
// queued on the agent belong to this source, and a different engine is a
// different source. Changing anything the password is sealed to requires the
// password again, because the agent will not open the old one.
func (s *Service) UpdateSource(ctx context.Context, tenantID, sourceID uuid.UUID, update Source) (Source, error) {
	current, err := s.repository.GetSource(ctx, tenantID, sourceID)
	if err != nil {
		return Source{}, err
	}
	if engine, ok := Engines[update.Engine]; !ok || engine != current.Engine {
		return Source{}, fmt.Errorf("%w: the engine of a source cannot change", ErrInvalid)
	}
	update.Engine = current.Engine
	update.ID, update.TenantID, update.AgentID = current.ID, tenantID, current.AgentID
	if err := validateSource(&update); err != nil {
		return Source{}, err
	}
	if len(update.SealedPassword) == 0 {
		if bindingChanged(current, update) {
			return Source{}, fmt.Errorf("%w: connection settings changed, enter the password again", ErrInvalid)
		}
		update.SealedPassword = current.SealedPassword
	}
	if err := s.repository.UpdateSource(ctx, update); err != nil {
		return Source{}, err
	}
	return update, nil
}

func bindingChanged(current, update Source) bool {
	return current.Host != update.Host || current.Port != update.Port || current.Database != update.Database ||
		current.Username != update.Username || current.TLS != update.TLS
}

// DeleteSource stops the agent serving the source; its history stays.
func (s *Service) DeleteSource(ctx context.Context, tenantID, sourceID uuid.UUID) error {
	return s.repository.DeleteSource(ctx, tenantID, sourceID)
}

// ActivateSource turns a checked draft into a source the agent scans and
// audits. Activating a source that is not a draft is a no-op.
func (s *Service) ActivateSource(ctx context.Context, tenantID, sourceID uuid.UUID) (Source, error) {
	if err := s.repository.ActivateSource(ctx, tenantID, sourceID); err != nil {
		return Source{}, err
	}
	return s.repository.GetSource(ctx, tenantID, sourceID)
}

func (s *Service) GetSource(ctx context.Context, tenantID, sourceID uuid.UUID) (Source, error) {
	return s.repository.GetSource(ctx, tenantID, sourceID)
}

func (s *Service) ListSources(ctx context.Context, tenantID uuid.UUID) ([]Source, error) {
	return s.repository.ListSources(ctx, tenantID)
}

// RecordProbes stores what an agent observed about its sources.
func (s *Service) RecordProbes(ctx context.Context, tenantID, agentID uuid.UUID, probes []Probe) error {
	return s.repository.RecordProbes(ctx, tenantID, agentID, probes)
}

// SourceList signs the current list of an agent's sources.
func (s *Service) SourceList(ctx context.Context, tenantID, agentID uuid.UUID) (SignedSources, error) {
	version, sources, err := s.repository.AgentSourceList(ctx, tenantID, agentID)
	if err != nil {
		return SignedSources{}, err
	}
	list := &agentv1.SourceList{Version: version, TenantId: tenantID.String(), AgentId: agentID.String()}
	for _, source := range sources {
		list.Sources = append(list.Sources, &agentv1.SourceDefinition{
			SourceId: source.ID.String(), Name: source.Key,
			Engine: agentv1.Engine(agentv1.Engine_value[source.Engine]),
			Host:   source.Host, Port: uint32(source.Port), Database: source.Database,
			Username: source.Username, Tls: tlsModes[source.TLS], AuditDirectory: source.AuditDirectory,
			MaxConnections: uint32(source.MaxConnections),
			SealedPassword: source.SealedPassword,
			ProbeOnly:      source.Draft,
		})
	}
	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(list)
	if err != nil {
		return SignedSources{}, fmt.Errorf("encode source list: %w", err)
	}
	return SignedSources{Version: version, Payload: payload, Signature: s.signer.Sign(pki.SourceListSigningInput(payload))}, nil
}

func validateSource(source *Source) error {
	if source.MaxConnections == 0 {
		source.MaxConnections = defaultMaxConnections
	}
	if source.TLS == "" {
		source.TLS = "verify-full"
	}
	switch {
	case !sourceNamePattern.MatchString(source.Key):
		return fmt.Errorf("%w: name must be lowercase letters, digits, - or _", ErrInvalid)
	case len(source.Host) > maxHostLength || !hostPattern.MatchString(source.Host):
		return fmt.Errorf("%w: host must be a name or an address", ErrInvalid)
	case source.Port < 1 || source.Port > maxPort:
		return fmt.Errorf("%w: port must be 1..65535", ErrInvalid)
	case !plainName(source.Database, maxNameRunes) || !plainName(source.Username, maxNameRunes):
		return fmt.Errorf("%w: database and user must be short names without control characters", ErrInvalid)
	case tlsModes[source.TLS] == agentv1.TLSMode_TLS_MODE_UNSPECIFIED:
		return fmt.Errorf("%w: tls must be verify-full, require or disable", ErrInvalid)
	case source.MaxConnections < 1 || source.MaxConnections > maxConnectionsLimit:
		return fmt.Errorf("%w: connections must be 1..8", ErrInvalid)
	case !validAuditDirectory(source.Engine, source.AuditDirectory):
		return fmt.Errorf("%w: audit directory must be an absolute clean path", ErrInvalid)
	case len(source.SealedPassword) > 0 && !sealedShape(source.SealedPassword):
		return fmt.Errorf("%w: password is not sealed to an agent", ErrInvalid)
	}
	return nil
}

func plainName(value string, maxRunes int) bool {
	return value != "" && utf8.ValidString(value) && utf8.RuneCountInString(value) <= maxRunes &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

// validAuditDirectory accepts any SQL Server path, which is a path on that
// server and may use its own conventions; file-based engines need a clean
// absolute path, which the agent then checks against its own allowlist.
func validAuditDirectory(engine, directory string) bool {
	if directory == "" {
		return true
	}
	if !plainName(directory, maxDirectoryRunes) {
		return false
	}
	return engine == "ENGINE_MSSQL" || (strings.HasPrefix(directory, "/") && path.Clean(directory) == directory)
}

// sealedShape checks only the envelope: the center cannot open the content.
func sealedShape(sealed []byte) bool {
	return len(sealed) >= minSealedPassword && len(sealed) <= maxSealedPassword &&
		sealed[0] == sealedVersion && sealed[1] == uncompressedPoint
}
