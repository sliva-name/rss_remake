// Package policy publishes signed, versioned configuration for agents.
package policy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

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
}

// Repository stores policy versions of one tenant.
type Repository interface {
	// Publish assigns the next version inside the transaction. encode receives
	// that version so the signature covers it.
	Publish(ctx context.Context, tenantID uuid.UUID, createdBy string, encode func(version uint64) (Signed, error)) (uint64, error)
	Latest(ctx context.Context, tenantID uuid.UUID) (Signed, error)
	// History lists every version, newest first.
	History(ctx context.Context, tenantID uuid.UUID) ([]Published, error)
	Version(ctx context.Context, tenantID uuid.UUID, version uint64) (Signed, error)
}

// Published is a stored version with who published it and when.
type Published struct {
	Signed
	CreatedBy string
	CreatedAt time.Time
}

// Signer signs serialized policies.
type Signer interface {
	Sign(payload []byte) []byte
}

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
	return s.repository.Publish(ctx, tenantID, createdBy, func(version uint64) (Signed, error) {
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(&agentv1.Policy{
			Version:         version,
			TenantId:        tenantID.String(),
			CustomDetectors: detectors,
			DefaultBudget:   budget,
		})
		if err != nil {
			return Signed{}, fmt.Errorf("encode policy: %w", err)
		}
		return Signed{Version: version, Payload: payload, Signature: s.signer.Sign(payload)}, nil
	})
}

func (s *Service) Latest(ctx context.Context, tenantID uuid.UUID) (Signed, error) {
	return s.repository.Latest(ctx, tenantID)
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
