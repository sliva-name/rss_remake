// Package fleet manages agents and the data sources they serve. Sources are
// defined here; their passwords are sealed to the serving agent (ADR-0006).
package fleet

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"dataguard/internal/core/oplog"
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
	ErrConflict     = errors.New("a source with this name already exists")
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
	// SealingPublicKey is what browsers seal passwords to. Agents enrolled
	// before ADR-0006 have none and cannot serve sources.
	SealingPublicKey []byte
	// ContractVersion is the contract of the last accepted heartbeat.
	ContractVersion uint32
	// RefusedContractVersion is set while the center refuses the contract the
	// agent speaks: from the refusal until the next accepted heartbeat.
	RefusedContractVersion *uint32
	// PolicyKeyEpoch is the policy key the agent trusts (ADR-0014).
	PolicyKeyEpoch uint32
}

// Heartbeat is what an agent says about itself on every call home.
type Heartbeat struct {
	Version        string
	Contract       uint32
	PolicyKeyEpoch uint32
	// AppliedSourcesVersion is ahead of the center's only after the center was
	// restored from a backup older than the agent's list. The center then moves
	// its version past it, or the agent would refuse the restored list as a
	// rollback.
	AppliedSourcesVersion uint64
}

type Capability struct {
	Capability string
	Support    string
	ReasonCode string
}

// Source is a database the center asks an agent to serve. Engine is the
// contract name, such as ENGINE_POSTGRESQL.
type Source struct {
	ID             uuid.UUID
	TenantID       uuid.UUID
	AgentID        uuid.UUID
	Key            string
	Engine         string
	Host           string
	Port           int
	Database       string
	Username       string
	TLS            string
	AuditDirectory string
	MaxConnections int
	SealedPassword []byte
	EngineVersion  string
	Capabilities   []Capability
	// StatusCode is what the agent said about opening the source; empty is fine.
	StatusCode string
	ProbedAt   *time.Time
	UpdatedAt  time.Time
	// Draft is a source being checked before it is saved: probed, not used.
	Draft bool
}

// Probe is an agent's report on one of its sources.
type Probe struct {
	SourceID      uuid.UUID
	EngineVersion string
	StatusCode    string
	Capabilities  []Capability
}

// Repository persists agents and sources within one tenant. A method that takes
// a journal entry writes it in the transaction of the change; a nil entry is a
// change the journal does not record, such as a draft.
type Repository interface {
	CreateEnrollmentToken(ctx context.Context, tenantID, environmentID uuid.UUID, hash []byte, expiresAt time.Time, entry oplog.Entry) error
	// ConsumeEnrollmentToken atomically spends a token and returns its
	// environment and who issued it.
	ConsumeEnrollmentToken(ctx context.Context, tenantID uuid.UUID, hash []byte) (uuid.UUID, oplog.Actor, error)
	CreateAgent(ctx context.Context, agent Agent, entry oplog.Entry) error
	GetAgent(ctx context.Context, tenantID, agentID uuid.UUID) (Agent, error)
	ListAgents(ctx context.Context, tenantID uuid.UUID) ([]Agent, error)
	// TouchAgent records a heartbeat, which clears a contract refusal, and
	// returns the agent's source list version.
	TouchAgent(ctx context.Context, tenantID, agentID uuid.UUID, beat Heartbeat) (uint64, error)
	RefuseContract(ctx context.Context, tenantID, agentID uuid.UUID, offered uint32) error
	RevokeAgent(ctx context.Context, tenantID, agentID uuid.UUID, entry oplog.Entry) error
	UpdateCertificateExpiry(ctx context.Context, tenantID, agentID uuid.UUID, expires time.Time) error
	// CreateSource, UpdateSource and DeleteSource also advance the serving
	// agent's source list version, in the same transaction.
	CreateSource(ctx context.Context, source Source, entry *oplog.Entry) error
	UpdateSource(ctx context.Context, source Source, entry *oplog.Entry) error
	DeleteSource(ctx context.Context, tenantID, sourceID uuid.UUID, entry *oplog.Entry) error
	ActivateSource(ctx context.Context, tenantID, sourceID uuid.UUID, entry oplog.Entry) error
	GetSource(ctx context.Context, tenantID, sourceID uuid.UUID) (Source, error)
	// ListSources returns live sources; deleted ones keep only their history.
	ListSources(ctx context.Context, tenantID uuid.UUID) ([]Source, error)
	// AgentSourceList returns the live sources of one agent with the list version.
	AgentSourceList(ctx context.Context, tenantID, agentID uuid.UUID) (uint64, []Source, error)
	// RecordProbes ignores reports on sources the agent does not serve.
	RecordProbes(ctx context.Context, tenantID, agentID uuid.UUID, probes []Probe) error
}

// CertificateIssuer signs agent certificates.
type CertificateIssuer interface {
	Issue(csrPEM []byte, tenantID, agentID uuid.UUID) (certificatePEM []byte, notAfter time.Time, err error)
}

// Signer signs source lists with the policy key.
type Signer interface {
	Sign(payload []byte) []byte
}

type Service struct {
	repository Repository
	issuer     CertificateIssuer
	signer     Signer
}

func NewService(repository Repository, issuer CertificateIssuer, signer Signer) *Service {
	return &Service{repository: repository, issuer: issuer, signer: signer}
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
	entry := oplog.New(ctx, oplog.EnrollmentTokenIssue, environmentID, "")
	if err := s.repository.CreateEnrollmentToken(ctx, tenantID, environmentID, hashToken(token), expiresAt, entry); err != nil {
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
func (s *Service) Enroll(ctx context.Context, token string, csrPEM, sealingPublicKey []byte, version string) (Enrollment, error) {
	tenantID, err := tenantOfToken(token)
	if err != nil {
		return Enrollment{}, err
	}
	if _, err := ecdh.P256().NewPublicKey(sealingPublicKey); err != nil {
		return Enrollment{}, fmt.Errorf("%w: sealing key is not a p-256 public key", ErrInvalid)
	}
	environmentID, issuer, err := s.repository.ConsumeEnrollmentToken(ctx, tenantID, hashToken(token))
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
		SealingPublicKey: sealingPublicKey,
	}
	// The agent joins on the authority of whoever issued its token.
	entry := oplog.New(oplog.WithActor(ctx, issuer), oplog.AgentEnroll, agentID, "").
		With(oplog.DetailEnvironment, environmentID.String())
	if err := s.repository.CreateAgent(ctx, agent, entry); err != nil {
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

// Heartbeat returns the agent's source list version, so it fetches the list
// only when it changed.
func (s *Service) Heartbeat(ctx context.Context, tenantID, agentID uuid.UUID, beat Heartbeat) (uint64, error) {
	return s.repository.TouchAgent(ctx, tenantID, agentID, beat)
}

// RefuseContract records that the center refused the contract version the agent
// offered, for the dashboard to explain.
func (s *Service) RefuseContract(ctx context.Context, tenantID, agentID uuid.UUID, offered uint32) error {
	return s.repository.RefuseContract(ctx, tenantID, agentID, offered)
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
	return s.repository.RevokeAgent(ctx, tenantID, agentID, oplog.New(ctx, oplog.AgentRevoke, agentID, ""))
}

func (s *Service) GetAgent(ctx context.Context, tenantID, agentID uuid.UUID) (Agent, error) {
	return s.repository.GetAgent(ctx, tenantID, agentID)
}

func (s *Service) ListAgents(ctx context.Context, tenantID uuid.UUID) ([]Agent, error) {
	return s.repository.ListAgents(ctx, tenantID)
}
