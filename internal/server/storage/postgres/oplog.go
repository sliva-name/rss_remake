package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"dataguard/internal/core/oplog"
)

// recordAction writes entry in tx, the transaction of the change it describes.
func recordAction(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, entry oplog.Entry) error {
	details := entry.Details
	if details == nil {
		details = map[string]string{}
	}
	const insert = `INSERT INTO operator_actions (id, tenant_id, actor_subject, actor_name, action, object_id, object_label, details)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	_, err := tx.Exec(ctx, insert, uuid.Must(uuid.NewV7()), tenantID, entry.Actor.Subject, entry.Actor.Name,
		string(entry.Action), entry.ObjectID, entry.ObjectLabel, details)
	return err
}

func (s *Store) ListActions(ctx context.Context, tenantID uuid.UUID, query oplog.Query) ([]oplog.Recorded, error) {
	var recorded []oplog.Recorded
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const list = `SELECT id, at, actor_subject, actor_name, action, object_id, object_label, details
			FROM operator_actions
			WHERE ($1::uuid IS NULL OR id < $1) AND ($2::uuid IS NULL OR object_id = $2)
			ORDER BY id DESC LIMIT $3`
		var err error
		recorded, err = queryAll(ctx, tx, func(row pgx.Row, item *oplog.Recorded) error {
			var action string
			err := row.Scan(&item.ID, &item.At, &item.Actor.Subject, &item.Actor.Name, &action,
				&item.ObjectID, &item.ObjectLabel, &item.Details)
			item.Action = oplog.Action(action)
			return err
		}, list, query.Before, query.ObjectID, query.Limit)
		return err
	})
	if err != nil {
		return nil, storageError("list operator actions", err)
	}
	return recorded, nil
}
