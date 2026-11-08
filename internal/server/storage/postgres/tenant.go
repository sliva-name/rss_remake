package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"dataguard/internal/core/oplog"
	"dataguard/internal/core/tenant"
)

func (s *Store) CreateTenant(ctx context.Context, created tenant.Tenant, entry oplog.Entry) error {
	err := s.inTenant(ctx, created.ID, func(tx pgx.Tx) error {
		const insert = `INSERT INTO tenants (id, name, created_at) VALUES ($1, $2, $3)`
		if _, err := tx.Exec(ctx, insert, created.ID, created.Name, created.CreatedAt); err != nil {
			return err
		}
		return recordAction(ctx, tx, created.ID, entry)
	})
	return translateConflict("create tenant", err)
}

func (s *Store) ListTenants(ctx context.Context) ([]tenant.Tenant, error) {
	tenants, err := queryAll(ctx, s.pool, func(row pgx.Row, item *tenant.Tenant) error {
		return row.Scan(&item.ID, &item.Name, &item.CreatedAt)
	}, `SELECT id, name, created_at FROM platform_list_tenants()`)
	if err != nil {
		return nil, storageError("list tenants", err)
	}
	return tenants, nil
}

func (s *Store) CreateEnvironment(ctx context.Context, created tenant.Environment, entry oplog.Entry) error {
	err := s.inTenant(ctx, created.TenantID, func(tx pgx.Tx) error {
		const insert = `INSERT INTO environments (id, tenant_id, name, kind, created_at) VALUES ($1, $2, $3, $4, $5)`
		if _, err := tx.Exec(ctx, insert, created.ID, created.TenantID, created.Name, created.Kind, created.CreatedAt); err != nil {
			return err
		}
		return recordAction(ctx, tx, created.TenantID, entry)
	})
	return translateConflict("create environment", err)
}

func (s *Store) ListEnvironments(ctx context.Context, tenantID uuid.UUID) ([]tenant.Environment, error) {
	var environments []tenant.Environment
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const query = `SELECT id, tenant_id, name, kind, created_at FROM environments ORDER BY name`
		var err error
		environments, err = queryAll(ctx, tx, func(row pgx.Row, item *tenant.Environment) error {
			return row.Scan(&item.ID, &item.TenantID, &item.Name, &item.Kind, &item.CreatedAt)
		}, query)
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
