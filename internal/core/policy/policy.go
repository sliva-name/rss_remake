// Package policy publishes signed, versioned configuration for agents.
package policy

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

var categoryPattern = regexp.MustCompile(`^CUSTOM(\.[A-Z][A-Z0-9_]*)+$`)

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

func validateDetectors(detectors []*agentv1.CustomDetector) error {
	for _, detector := range detectors {
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
