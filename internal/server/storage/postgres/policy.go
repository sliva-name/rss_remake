package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"dataguard/internal/core/oplog"
	"dataguard/internal/core/policy"
)

func (s *Store) Publish(ctx context.Context, tenantID uuid.UUID, createdBy string, encode func(version uint64) (policy.Signed, oplog.Entry, error)) (uint64, error) {
	var version uint64
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// The advisory lock serializes publishers of one tenant, so two concurrent
		// publishes cannot sign the same version.
		const lock = `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`
		if _, err := tx.Exec(ctx, lock, tenantID.String()); err != nil {
			return err
		}
		const next = `SELECT COALESCE(max(version), 0) + 1 FROM policies`
		if err := tx.QueryRow(ctx, next).Scan(&version); err != nil {
			return err
		}
		signed, entry, err := encode(version)
		if err != nil {
			return err
		}
		const insert = `INSERT INTO policies (tenant_id, version, payload, signature, created_by) VALUES ($1, $2, $3, $4, $5)`
		if _, err := tx.Exec(ctx, insert, tenantID, version, signed.Payload, signed.Signature, createdBy); err != nil {
			return err
		}
		return recordAction(ctx, tx, tenantID, entry)
	})
	if err != nil {
		return 0, storageError("publish policy", err)
	}
	return version, nil
}

func (s *Store) History(ctx context.Context, tenantID uuid.UUID) ([]policy.Published, error) {
	var history []policy.Published
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		history, err = queryAll(ctx, tx, func(row pgx.Row, item *policy.Published) error {
			return row.Scan(&item.Version, &item.Payload, &item.Signature, &item.CreatedBy, &item.CreatedAt)
		}, `SELECT version, payload, signature, created_by, created_at FROM policies ORDER BY version DESC`)
		return err
	})
	if err != nil {
		return nil, storageError("list policy versions", err)
	}
	return history, nil
}

func (s *Store) Version(ctx context.Context, tenantID uuid.UUID, version uint64) (policy.Signed, error) {
	var signed policy.Signed
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const query = `SELECT version, payload, signature FROM policies WHERE version = $1`
		return tx.QueryRow(ctx, query, version).Scan(&signed.Version, &signed.Payload, &signed.Signature)
	})
	if err := readError("read policy version", err, policy.ErrNotFound); err != nil {
		return policy.Signed{}, err
	}
	return signed, nil
}

func (s *Store) Latest(ctx context.Context, tenantID uuid.UUID) (policy.Signed, error) {
	var signed policy.Signed
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const query = `SELECT version, payload, signature FROM policies ORDER BY version DESC LIMIT 1`
		return tx.QueryRow(ctx, query).Scan(&signed.Version, &signed.Payload, &signed.Signature)
	})
	if err := readError("read policy", err, policy.ErrNotFound); err != nil {
		return policy.Signed{}, err
	}
	return signed, nil
}
