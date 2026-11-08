package postgres

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"dataguard/internal/core/preference"
)

// asOwner runs work in the owner's tenant with the owner set for the row
// policy of user_preferences, the second lock after the tenant.
func (s *Store) asOwner(ctx context.Context, owner preference.Owner, work func(pgx.Tx) error) error {
	return s.inTenant(ctx, owner.TenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.subject', $1, true)`, owner.Subject); err != nil {
			return err
		}
		return work(tx)
	})
}

func (s *Store) GetPreference(ctx context.Context, owner preference.Owner, key string) (json.RawMessage, error) {
	var value json.RawMessage
	err := s.asOwner(ctx, owner, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT value FROM user_preferences WHERE subject = $1 AND key = $2`, owner.Subject, key).Scan(&value)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, storageError("get preference", err)
	}
	return value, nil
}

func (s *Store) PutPreference(ctx context.Context, owner preference.Owner, key string, value json.RawMessage) error {
	err := s.asOwner(ctx, owner, func(tx pgx.Tx) error {
		const upsert = `INSERT INTO user_preferences (tenant_id, subject, key, value) VALUES ($1, $2, $3, $4)
			ON CONFLICT (tenant_id, subject, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`
		_, err := tx.Exec(ctx, upsert, owner.TenantID, owner.Subject, key, value)
		return err
	})
	if err != nil {
		return storageError("save preference", err)
	}
	return nil
}
