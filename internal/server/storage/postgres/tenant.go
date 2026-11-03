package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"dataguard/internal/core/tenant"
)

func (s *Store) CreateTenant(ctx context.Context, created tenant.Tenant) error {
	err := s.inTenant(ctx, created.ID, func(tx pgx.Tx) error {
		const insert = `INSERT INTO tenants (id, name, created_at) VALUES ($1, $2, $3)`
		_, err := tx.Exec(ctx, insert, created.ID, created.Name, created.CreatedAt)
		return err
	})
	return translateConflict("create tenant", err)
}

func (s *Store) ListTenants(ctx context.Context) ([]tenant.Tenant, error) {
	rows, err := s.pool.Query(ctx, `SELECT id, name, created_at FROM platform_list_tenants()`)
	if err != nil {
		return nil, storageError("list tenants", err)
	}
	tenants, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (tenant.Tenant, error) {
		var item tenant.Tenant
		err := row.Scan(&item.ID, &item.Name, &item.CreatedAt)
		return item, err
	})
	if err != nil {
		return nil, storageError("list tenants", err)
	}
	return tenants, nil
}

func (s *Store) CreateEnvironment(ctx context.Context, created tenant.Environment) error {
	err := s.inTenant(ctx, created.TenantID, func(tx pgx.Tx) error {
		const insert = `INSERT INTO environments (id, tenant_id, name, kind, created_at) VALUES ($1, $2, $3, $4, $5)`
		_, err := tx.Exec(ctx, insert, created.ID, created.TenantID, created.Name, created.Kind, created.CreatedAt)
		return err
	})
	return translateConflict("create environment", err)
}

func (s *Store) ListEnvironments(ctx context.Context, tenantID uuid.UUID) ([]tenant.Environment, error) {
	var environments []tenant.Environment
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const query = `SELECT id, tenant_id, name, kind, created_at FROM environments ORDER BY name`
		rows, err := tx.Query(ctx, query)
		if err != nil {
			return err
		}
		environments, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (tenant.Environment, error) {
			var item tenant.Environment
			err := row.Scan(&item.ID, &item.TenantID, &item.Name, &item.Kind, &item.CreatedAt)
			return item, err
		})
		return err
	})
	if err != nil {
		return nil, storageError("list environments", err)
	}
	return environments, nil
}

func translateConflict(op string, err error) error {
	switch {
	case err == nil:
		return nil
	case isUniqueViolation(err):
		return tenant.ErrConflict
	default:
		return storageError(op, err)
	}
}
