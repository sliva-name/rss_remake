// Package tenant manages organizations and their environments.
package tenant

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"

	"dataguard/internal/core/oplog"
)

const (
	maxTenantNameRunes      = 200
	maxEnvironmentNameRunes = 100
)

// Environment kinds.
const (
	KindDevelopment = "development"
	KindTesting     = "testing"
	KindProduction  = "production"
)

var (
	ErrInvalid  = errors.New("invalid input")
	ErrConflict = errors.New("name already exists")
)

type Tenant struct {
	ID        uuid.UUID
	Name      string
	CreatedAt time.Time
}

type Environment struct {
	ID        uuid.UUID
	TenantID  uuid.UUID
	Name      string
	Kind      string
	CreatedAt time.Time
}

// Repository persists tenants. Except for ListTenants, which is a platform
// operation, all access is scoped to one tenant.
type Repository interface {
	// CreateTenant and CreateEnvironment write entry in the same transaction.
	CreateTenant(ctx context.Context, tenant Tenant, entry oplog.Entry) error
	ListTenants(ctx context.Context) ([]Tenant, error)
	CreateEnvironment(ctx context.Context, environment Environment, entry oplog.Entry) error
	ListEnvironments(ctx context.Context, tenantID uuid.UUID) ([]Environment, error)
}

type Service struct {
	repository Repository
}

func NewService(repository Repository) *Service {
	return &Service{repository: repository}
}

func (s *Service) CreateTenant(ctx context.Context, name string) (Tenant, error) {
	name = strings.TrimSpace(name)
	if err := checkName(name, maxTenantNameRunes); err != nil {
		return Tenant{}, err
	}
	created := Tenant{ID: uuid.Must(uuid.NewV7()), Name: name, CreatedAt: time.Now().UTC()}
	if err := s.repository.CreateTenant(ctx, created, oplog.New(ctx, oplog.TenantCreate, created.ID, name)); err != nil {
		return Tenant{}, err
	}
	return created, nil
}

func (s *Service) ListTenants(ctx context.Context) ([]Tenant, error) {
	return s.repository.ListTenants(ctx)
}

func (s *Service) CreateEnvironment(ctx context.Context, tenantID uuid.UUID, name, kind string) (Environment, error) {
	name = strings.TrimSpace(name)
	if err := checkName(name, maxEnvironmentNameRunes); err != nil {
		return Environment{}, err
	}
	if kind != KindDevelopment && kind != KindTesting && kind != KindProduction {
		return Environment{}, fmt.Errorf("%w: unknown environment kind", ErrInvalid)
	}
	created := Environment{ID: uuid.Must(uuid.NewV7()), TenantID: tenantID, Name: name, Kind: kind, CreatedAt: time.Now().UTC()}
	if err := s.repository.CreateEnvironment(ctx, created, oplog.New(ctx, oplog.EnvironmentCreate, created.ID, name)); err != nil {
		return Environment{}, err
	}
	return created, nil
}

func (s *Service) ListEnvironments(ctx context.Context, tenantID uuid.UUID) ([]Environment, error) {
	return s.repository.ListEnvironments(ctx, tenantID)
}

func checkName(name string, maxRunes int) error {
	if name == "" || len([]rune(name)) > maxRunes {
		return fmt.Errorf("%w: name must have 1 to %d characters", ErrInvalid, maxRunes)
	}
	return nil
}
