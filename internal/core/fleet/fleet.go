// Package fleet manages agents and the data sources they report. The center
// knows sources only by key and id; connection details stay on the agent.
package fleet

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

const (
	enrollmentTokenLifetime = 24 * time.Hour
	secretBytes             = 32
	tokenSeparator          = "_"
)

// Agent statuses.
const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
)

var (
	ErrInvalidToken = errors.New("enrollment token is invalid, expired or used")
	ErrNotActive    = errors.New("agent is not active")
	ErrNotFound     = errors.New("not found")
	ErrInvalid      = errors.New("invalid input")
)

type Agent struct {
	ID                 uuid.UUID
	TenantID           uuid.UUID
	EnvironmentID      uuid.UUID
	Status             string
	Version            string
	CertificateExpires time.Time
	LastSeenAt         *time.Time
	CreatedAt          time.Time
}

type Capability struct {
	Capability string
	Support    string
	ReasonCode string
}

type Source struct {
	ID            uuid.UUID
	TenantID      uuid.UUID
	AgentID       uuid.UUID
	Key           string
	Engine        string
	EngineVersion string
	Capabilities  []Capability
	UpdatedAt     time.Time
}

// Repository persists agents and sources within one tenant.
type Repository interface {
	CreateEnrollmentToken(ctx context.Context, tenantID, environmentID uuid.UUID, hash []byte, expiresAt time.Time) error
	// ConsumeEnrollmentToken atomically spends a token and returns its environment.
	ConsumeEnrollmentToken(ctx context.Context, tenantID uuid.UUID, hash []byte) (uuid.UUID, error)
	CreateAgent(ctx context.Context, agent Agent) error
	GetAgent(ctx context.Context, tenantID, agentID uuid.UUID) (Agent, error)
	ListAgents(ctx context.Context, tenantID uuid.UUID) ([]Agent, error)
	TouchAgent(ctx context.Context, tenantID, agentID uuid.UUID, version string) error
	RevokeAgent(ctx context.Context, tenantID, agentID uuid.UUID) error
	UpdateCertificateExpiry(ctx context.Context, tenantID, agentID uuid.UUID, expires time.Time) error
	// UpsertSource keeps the id of a known source key and replaces its capabilities.
	UpsertSource(ctx context.Context, source Source) (uuid.UUID, error)
	ListSources(ctx context.Context, tenantID uuid.UUID) ([]Source, error)
}

// CertificateIssuer signs agent certificates.
type CertificateIssuer interface {
	Issue(csrPEM []byte, tenantID, agentID uuid.UUID) (certificatePEM []byte, notAfter time.Time, err error)
}

type Service struct {
	repository Repository
	issuer     CertificateIssuer
}

func NewService(repository Repository, issuer CertificateIssuer) *Service {
	return &Service{repository: repository, issuer: issuer}
}

// CreateEnrollmentToken returns the plaintext token once; only its hash is
// stored. The token embeds the tenant so the lookup can run under row security.
func (s *Service) CreateEnrollmentToken(ctx context.Context, tenantID, environmentID uuid.UUID) (string, time.Time, error) {
	secret := make([]byte, secretBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", time.Time{}, fmt.Errorf("generate token: %w", err)
	}
	token := hex.EncodeToString(tenantID[:]) + tokenSeparator + base64.RawURLEncoding.EncodeToString(secret)
	expiresAt := time.Now().UTC().Add(enrollmentTokenLifetime)
	if err := s.repository.CreateEnrollmentToken(ctx, tenantID, environmentID, hashToken(token), expiresAt); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

// Enrollment is the outcome of a successful Enroll.
type Enrollment struct {
	TenantID       uuid.UUID
	AgentID        uuid.UUID
	CertificatePEM []byte
}

// Enroll spends the token first. A crash afterwards wastes the token, which an
// operator can reissue, whereas the reverse order could enroll an agent twice.
func (s *Service) Enroll(ctx context.Context, token string, csrPEM []byte, version string) (Enrollment, error) {
	tenantID, err := tenantOfToken(token)
	if err != nil {
		return Enrollment{}, err
	}
	environmentID, err := s.repository.ConsumeEnrollmentToken(ctx, tenantID, hashToken(token))
	if err != nil {
		return Enrollment{}, err
	}
	agentID := uuid.Must(uuid.NewV7())
	certificate, notAfter, err := s.issuer.Issue(csrPEM, tenantID, agentID)
	if err != nil {
		return Enrollment{}, fmt.Errorf("%w: certificate request rejected", ErrInvalid)
	}
	agent := Agent{
		ID: agentID, TenantID: tenantID, EnvironmentID: environmentID, Status: StatusActive,
		Version: version, CertificateExpires: notAfter, CreatedAt: time.Now().UTC(),
	}
	if err := s.repository.CreateAgent(ctx, agent); err != nil {
		return Enrollment{}, err
	}
	return Enrollment{TenantID: tenantID, AgentID: agentID, CertificatePEM: certificate}, nil
}

func tenantOfToken(token string) (uuid.UUID, error) {
	prefix, _, found := strings.Cut(token, tokenSeparator)
	if !found {
		return uuid.Nil, ErrInvalidToken
	}
	tenantID, err := uuid.Parse(prefix)
	if err != nil {
		return uuid.Nil, ErrInvalidToken
	}
	return tenantID, nil
}

func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// Authorize is called on every agent request, which is what makes revocation
// immediate without certificate revocation lists.
func (s *Service) Authorize(ctx context.Context, tenantID, agentID uuid.UUID) error {
	agent, err := s.repository.GetAgent(ctx, tenantID, agentID)
	if err != nil {
		return err
	}
	if agent.Status != StatusActive {
		return ErrNotActive
	}
	return nil
}

func (s *Service) Heartbeat(ctx context.Context, tenantID, agentID uuid.UUID, version string) error {
	return s.repository.TouchAgent(ctx, tenantID, agentID, version)
}

func (s *Service) RenewCertificate(ctx context.Context, tenantID, agentID uuid.UUID, csrPEM []byte) ([]byte, error) {
	certificate, notAfter, err := s.issuer.Issue(csrPEM, tenantID, agentID)
	if err != nil {
		return nil, fmt.Errorf("%w: certificate request rejected", ErrInvalid)
	}
	if err := s.repository.UpdateCertificateExpiry(ctx, tenantID, agentID, notAfter); err != nil {
		return nil, err
	}
	return certificate, nil
}

func (s *Service) Revoke(ctx context.Context, tenantID, agentID uuid.UUID) error {
	return s.repository.RevokeAgent(ctx, tenantID, agentID)
}

func (s *Service) ListAgents(ctx context.Context, tenantID uuid.UUID) ([]Agent, error) {
	return s.repository.ListAgents(ctx, tenantID)
}

func (s *Service) ListSources(ctx context.Context, tenantID uuid.UUID) ([]Source, error) {
	return s.repository.ListSources(ctx, tenantID)
}

// ReportSources records what an agent observes and maps each key to a stable id.
func (s *Service) ReportSources(ctx context.Context, tenantID, agentID uuid.UUID, sources []Source) (map[string]uuid.UUID, error) {
	assignments := make(map[string]uuid.UUID, len(sources))
	for _, source := range sources {
		source.TenantID = tenantID
		source.AgentID = agentID
		id, err := s.repository.UpsertSource(ctx, source)
		if err != nil {
			return nil, err
		}
		assignments[source.Key] = id
	}
	return assignments, nil
}
