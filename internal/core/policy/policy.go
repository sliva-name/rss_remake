// Package policy publishes signed, versioned configuration for agents.
package policy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"dataguard/internal/core/oplog"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

var categoryPattern = regexp.MustCompile(`^CUSTOM(\.[A-Z][A-Z0-9_]*)+$`)

// Limits declared in the API schema. Every agent compiles and runs each pattern
// on every sampled value, so they bound the agent's work, not only the request.
const (
	maxDetectors    = 200
	maxPatternRunes = 512
)

var (
	ErrNotFound = errors.New("policy not found")
	ErrInvalid  = errors.New("invalid policy")
)

// Signed is a stored policy; Payload is the exact bytes that were signed.
type Signed struct {
	Version   uint64
	Payload   []byte
	Signature []byte
	// KeyEpoch is the epoch of the policy key that made Signature.
	KeyEpoch uint32
}

// Repository stores policy versions of one tenant.
type Repository interface {
	// Publish assigns the next version inside the transaction. encode receives
	// that version so the signature covers it, and returns the journal entry
	// to write in the same transaction.
	Publish(ctx context.Context, tenantID uuid.UUID, createdBy string, encode func(version uint64) (Signed, oplog.Entry, error)) (uint64, error)
	Latest(ctx context.Context, tenantID uuid.UUID) (Signed, error)
	// History lists every version, newest first.
	History(ctx context.Context, tenantID uuid.UUID) ([]Published, error)
	Version(ctx context.Context, tenantID uuid.UUID, version uint64) (Signed, error)
	// Resign replaces the signature of a stored version.
	Resign(ctx context.Context, tenantID uuid.UUID, signed Signed) error
}

// Published is a stored version with who published it and when.
type Published struct {
	Signed
	CreatedBy string
	CreatedAt time.Time
}

// Signer signs serialized policies with the current policy key and checks
// signatures made by the keys of earlier epochs.
type Signer interface {
	Sign(payload []byte) []byte
	Epoch() uint32
	Verify(epoch uint32, payload, signature []byte) error
}

var (
	// ErrTampered means a stored policy does not match its signature: it was
	// changed in the database, not published.
	ErrTampered = errors.New("stored policy does not match its signature")
	// ErrKeyRotated means another server instance already signs with a newer
	// key than this one loaded at start: this instance must be restarted.
	ErrKeyRotated = errors.New("the policy key was rotated after this server started")
)

type Service struct {
	repository Repository
	signer     Signer
}

func NewService(repository Repository, signer Signer) *Service {
	return &Service{repository: repository, signer: signer}
}

// Publish validates and signs a new version.
func (s *Service) Publish(ctx context.Context, tenantID uuid.UUID, createdBy string, detectors []*agentv1.CustomDetector, budget *agentv1.ScanBudget) (uint64, error) {
	if err := validateDetectors(detectors); err != nil {
		return 0, err
	}
	return s.repository.Publish(ctx, tenantID, createdBy, func(version uint64) (Signed, oplog.Entry, error) {
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.Policy{
			Version:         version,
			TenantId:        tenantID.String(),
			CustomDetectors: detectors,
			DefaultBudget:   budget,
		})
		if err != nil {
			return Signed{}, oplog.Entry{}, fmt.Errorf("encode policy: %w", err)
		}
		// The policy belongs to the organization, so the organization is the object.
		entry := oplog.New(ctx, oplog.PolicyPublish, tenantID, "").With(oplog.DetailVersion, strconv.FormatUint(version, 10))
		return Signed{Version: version, Payload: payload, Signature: s.signer.Sign(payload), KeyEpoch: s.signer.Epoch()}, entry, nil
	})
}

// Latest returns the newest version signed by the current key. A version signed
// before the key was rotated is checked with the key that signed it and signed
// again: agents trust only the current key, so a leaked old key signs nothing
// they accept (ADR-0014).
func (s *Service) Latest(ctx context.Context, tenantID uuid.UUID) (Signed, error) {
	signed, err := s.repository.Latest(ctx, tenantID)
	if err != nil || signed.KeyEpoch == s.signer.Epoch() {
		return signed, err
	}
	if signed.KeyEpoch > s.signer.Epoch() {
		return Signed{}, ErrKeyRotated
	}
	if err := s.signer.Verify(signed.KeyEpoch, signed.Payload, signed.Signature); err != nil {
		return Signed{}, ErrTampered
	}
	signed.Signature, signed.KeyEpoch = s.signer.Sign(signed.Payload), s.signer.Epoch()
	if err := s.repository.Resign(ctx, tenantID, signed); err != nil {
		return Signed{}, err
	}
	return signed, nil
}

// LatestVersion is the newest version number, without its signature: enough for
// a heartbeat to tell an agent whether to fetch.
func (s *Service) LatestVersion(ctx context.Context, tenantID uuid.UUID) (uint64, error) {
	signed, err := s.repository.Latest(ctx, tenantID)
	if errors.Is(err, ErrNotFound) {
		return 0, nil
	}
	return signed.Version, err
}

func (s *Service) History(ctx context.Context, tenantID uuid.UUID) ([]Published, error) {
	return s.repository.History(ctx, tenantID)
}

func (s *Service) Version(ctx context.Context, tenantID uuid.UUID, version uint64) (Signed, error) {
	return s.repository.Version(ctx, tenantID, version)
}

// Decode returns the content of a signed policy.
func Decode(signed Signed) (*agentv1.Policy, error) {
	decoded := &agentv1.Policy{}
	if err := proto.Unmarshal(signed.Payload, decoded); err != nil {
		return nil, fmt.Errorf("decode policy: %w", err)
	}
	return decoded, nil
}

func validateDetectors(detectors []*agentv1.CustomDetector) error {
	if len(detectors) > maxDetectors {
		return fmt.Errorf("%w: at most %d custom detectors", ErrInvalid, maxDetectors)
	}
	for _, detector := range detectors {
		if utf8.RuneCountInString(detector.GetValuePattern()) > maxPatternRunes ||
			utf8.RuneCountInString(detector.GetNamePattern()) > maxPatternRunes {
			return fmt.Errorf("%w: a pattern is longer than %d characters", ErrInvalid, maxPatternRunes)
		}
		if !categoryPattern.MatchString(detector.GetCategoryId()) {
			return fmt.Errorf("%w: custom category must look like CUSTOM.NAME", ErrInvalid)
		}
		if detector.GetValuePattern() == "" && detector.GetNamePattern() == "" {
			return fmt.Errorf("%w: detector needs a value or name pattern", ErrInvalid)
		}
		for _, pattern := range []string{detector.GetValuePattern(), detector.GetNamePattern()} {
			if _, err := regexp.Compile(pattern); err != nil {
				return fmt.Errorf("%w: pattern does not compile", ErrInvalid)
			}
		}
	}
	return nil
}
