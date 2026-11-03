// Package identity keeps the agent's enrollment state on disk: its key,
// certificate, pinned keys and last accepted policy.
package identity

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/pki"
)

const (
	keyFile       = "agent.key"
	certFile      = "agent.crt"
	caFile        = "center-ca.crt"
	stateFile     = "identity.json"
	policyFile    = "policy.bin"
	secretMode    = 0o600
	directoryMode = 0o700
)

var (
	// ErrNotEnrolled means the agent must run enrollment first.
	ErrNotEnrolled = errors.New("agent is not enrolled")
	// ErrPolicyRollback rejects a policy older than the one already applied.
	ErrPolicyRollback = errors.New("policy version is older than the applied one")
)

type persistedState struct {
	TenantID        uuid.UUID `json:"tenant_id"`
	AgentID         uuid.UUID `json:"agent_id"`
	PolicyPublicKey []byte    `json:"policy_public_key"`
	PolicyVersion   uint64    `json:"policy_version"`
}

// Store is the agent's local identity. It is safe for concurrent use because
// the TLS stack reads the certificate while renewal replaces it.
type Store struct {
	directory string

	mu          sync.RWMutex
	state       persistedState
	certificate *tls.Certificate
}

// Enrollment is what the center returns when an agent joins.
type Enrollment struct {
	TenantID        uuid.UUID
	AgentID         uuid.UUID
	KeyPEM          []byte
	CertificatePEM  []byte
	CACertificate   []byte
	PolicyPublicKey []byte
}

// Save persists a new enrollment.
func Save(directory string, enrollment Enrollment) error {
	if err := os.MkdirAll(directory, directoryMode); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	files := map[string][]byte{
		keyFile:  enrollment.KeyPEM,
		certFile: enrollment.CertificatePEM,
		caFile:   enrollment.CACertificate,
	}
	for name, content := range files {
		if err := writeAtomic(filepath.Join(directory, name), content); err != nil {
			return err
		}
	}
	return writeState(directory, persistedState{
		TenantID: enrollment.TenantID, AgentID: enrollment.AgentID, PolicyPublicKey: enrollment.PolicyPublicKey,
	})
}

// Open loads an enrolled identity.
func Open(directory string) (*Store, error) {
	data, err := os.ReadFile(filepath.Join(filepath.Clean(directory), stateFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, fmt.Errorf("read identity: %w", err)
	}
	store := &Store{directory: directory}
	if err := json.Unmarshal(data, &store.state); err != nil {
		return nil, fmt.Errorf("parse identity: %w", err)
	}
	if err := store.loadCertificate(); err != nil {
		return nil, err
	}
	return store, nil
}

func (s *Store) loadCertificate() error {
	certificate, err := tls.LoadX509KeyPair(filepath.Join(s.directory, certFile), filepath.Join(s.directory, keyFile))
	if err != nil {
		return fmt.Errorf("load agent certificate: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certificate = &certificate
	return nil
}

func (s *Store) TenantID() uuid.UUID { return s.state.TenantID }
func (s *Store) AgentID() uuid.UUID  { return s.state.AgentID }

// ClientCertificate satisfies tls.Config.GetClientCertificate, so renewal takes
// effect on the next connection without a restart.
func (s *Store) ClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.certificate, nil
}

// RenewalDue reports whether more than half of the certificate's lifetime has
// passed, which leaves room for retries while the center is unavailable.
func (s *Store) RenewalDue(now time.Time) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	leaf, err := x509.ParseCertificate(s.certificate.Certificate[0])
	if err != nil {
		return false, fmt.Errorf("parse agent certificate: %w", err)
	}
	return now.After(leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) / 2)), nil
}

// ReplaceCertificate installs a renewed certificate with its new key.
func (s *Store) ReplaceCertificate(keyPEM, certificatePEM []byte) error {
	if _, err := tls.X509KeyPair(certificatePEM, keyPEM); err != nil {
		return fmt.Errorf("verify renewed certificate: %w", err)
	}
	if err := writeAtomic(filepath.Join(s.directory, keyFile), keyPEM); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(s.directory, certFile), certificatePEM); err != nil {
		return err
	}
	return s.loadCertificate()
}

// PolicyVersion returns the version of the last accepted policy.
func (s *Store) PolicyVersion() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.PolicyVersion
}

// AcceptPolicy verifies the signature, the owning tenant and the version
// before storing. Only then does the policy count as applied.
func (s *Store) AcceptPolicy(payload, signature []byte) (*agentv1.Policy, error) {
	if err := pki.VerifyPolicy(s.state.PolicyPublicKey, payload, signature); err != nil {
		return nil, err
	}
	policy := &agentv1.Policy{}
	if err := proto.Unmarshal(payload, policy); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	if policy.GetTenantId() != s.state.TenantID.String() {
		return nil, errors.New("policy belongs to another tenant")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if policy.GetVersion() < s.state.PolicyVersion {
		return nil, ErrPolicyRollback
	}
	if err := writeAtomic(filepath.Join(s.directory, policyFile), payload); err != nil {
		return nil, err
	}
	updated := s.state
	updated.PolicyVersion = policy.GetVersion()
	if err := writeState(s.directory, updated); err != nil {
		return nil, err
	}
	s.state = updated
	return policy, nil
}

// LoadPolicy returns the applied policy, or nil if none was accepted yet. The
// file was verified before it was written and the state directory is private.
func (s *Store) LoadPolicy() (*agentv1.Policy, error) {
	data, err := os.ReadFile(filepath.Join(filepath.Clean(s.directory), policyFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read policy: %w", err)
	}
	policy := &agentv1.Policy{}
	if err := proto.Unmarshal(data, policy); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	return policy, nil
}

func writeState(directory string, state persistedState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return fmt.Errorf("encode identity: %w", err)
	}
	return writeAtomic(filepath.Join(directory, stateFile), data)
}

// writeAtomic renames over the target, so a crash leaves the old or the new
// file and never a truncated key.
func writeAtomic(path string, content []byte) error {
	temporary := path + ".tmp"
	if err := os.WriteFile(temporary, content, secretMode); err != nil {
		return fmt.Errorf("write state file: %w", err)
	}
	if err := os.Rename(temporary, path); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}
	return nil
}
