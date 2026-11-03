package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"dataguard/internal/core/fleet"
)

func (s *Store) CreateEnrollmentToken(ctx context.Context, tenantID, environmentID uuid.UUID, hash []byte, expiresAt time.Time) error {
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var exists bool
		const check = `SELECT EXISTS (SELECT 1 FROM environments WHERE id = $1)`
		if err := tx.QueryRow(ctx, check, environmentID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fleet.ErrNotFound
		}
		const insert = `INSERT INTO enrollment_tokens (id, tenant_id, environment_id, token_hash, expires_at)
			VALUES ($1, $2, $3, $4, $5)`
		_, err := tx.Exec(ctx, insert, uuid.Must(uuid.NewV7()), tenantID, environmentID, hash, expiresAt)
		return err
	})
	if errors.Is(err, fleet.ErrNotFound) {
		return err
	}
	if err != nil {
		return storageError("create enrollment token", err)
	}
	return nil
}

func (s *Store) ConsumeEnrollmentToken(ctx context.Context, tenantID uuid.UUID, hash []byte) (uuid.UUID, error) {
	var environmentID uuid.UUID
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const consume = `UPDATE enrollment_tokens SET used_at = now()
			WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
			RETURNING environment_id`
		return tx.QueryRow(ctx, consume, hash).Scan(&environmentID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, fleet.ErrInvalidToken
	}
	if err != nil {
		return uuid.Nil, storageError("consume enrollment token", err)
	}
	return environmentID, nil
}

func (s *Store) CreateAgent(ctx context.Context, agent fleet.Agent) error {
	err := s.inTenant(ctx, agent.TenantID, func(tx pgx.Tx) error {
		const insert = `INSERT INTO agents (id, tenant_id, environment_id, status, version, certificate_expires, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`
		_, err := tx.Exec(ctx, insert, agent.ID, agent.TenantID, agent.EnvironmentID, agent.Status,
			agent.Version, agent.CertificateExpires, agent.CreatedAt)
		return err
	})
	if err != nil {
		return storageError("create agent", err)
	}
	return nil
}

const agentColumns = `id, tenant_id, environment_id, status, version, certificate_expires, last_seen_at, created_at`

func scanAgent(row pgx.Row) (fleet.Agent, error) {
	var agent fleet.Agent
	err := row.Scan(&agent.ID, &agent.TenantID, &agent.EnvironmentID, &agent.Status, &agent.Version,
		&agent.CertificateExpires, &agent.LastSeenAt, &agent.CreatedAt)
	return agent, err
}

func (s *Store) GetAgent(ctx context.Context, tenantID, agentID uuid.UUID) (fleet.Agent, error) {
	var agent fleet.Agent
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		agent, err = scanAgent(tx.QueryRow(ctx, `SELECT `+agentColumns+` FROM agents WHERE id = $1`, agentID))
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return fleet.Agent{}, fleet.ErrNotFound
	}
	if err != nil {
		return fleet.Agent{}, storageError("get agent", err)
	}
	return agent, nil
}

func (s *Store) ListAgents(ctx context.Context, tenantID uuid.UUID) ([]fleet.Agent, error) {
	var agents []fleet.Agent
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+agentColumns+` FROM agents ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		agents, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (fleet.Agent, error) {
			return scanAgent(row)
		})
		return err
	})
	if err != nil {
		return nil, storageError("list agents", err)
	}
	return agents, nil
}

func (s *Store) TouchAgent(ctx context.Context, tenantID, agentID uuid.UUID, version string) error {
	const update = `UPDATE agents SET last_seen_at = now(), version = $2 WHERE id = $1`
	return s.updateAgent(ctx, tenantID, "touch agent", update, agentID, version)
}

func (s *Store) RevokeAgent(ctx context.Context, tenantID, agentID uuid.UUID) error {
	const update = `UPDATE agents SET status = 'revoked', revoked_at = now() WHERE id = $1`
	return s.updateAgent(ctx, tenantID, "revoke agent", update, agentID)
}

func (s *Store) UpdateCertificateExpiry(ctx context.Context, tenantID, agentID uuid.UUID, expires time.Time) error {
	const update = `UPDATE agents SET certificate_expires = $2 WHERE id = $1`
	return s.updateAgent(ctx, tenantID, "update certificate expiry", update, agentID, expires)
}

func (s *Store) updateAgent(ctx context.Context, tenantID uuid.UUID, op, statement string, args ...any) error {
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		result, err := tx.Exec(ctx, statement, args...)
		if err != nil {
			return err
		}
		if result.RowsAffected() == 0 {
			return fleet.ErrNotFound
		}
		return nil
	})
	if errors.Is(err, fleet.ErrNotFound) {
		return err
	}
	if err != nil {
		return storageError(op, err)
	}
	return nil
}

func (s *Store) UpsertSource(ctx context.Context, source fleet.Source) (uuid.UUID, error) {
	var sourceID uuid.UUID
	err := s.inTenant(ctx, source.TenantID, func(tx pgx.Tx) error {
		const upsert = `INSERT INTO sources (id, tenant_id, agent_id, source_key, engine, engine_version)
			VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (agent_id, source_key) DO UPDATE
				SET engine = EXCLUDED.engine, engine_version = EXCLUDED.engine_version, updated_at = now()
			RETURNING id`
		err := tx.QueryRow(ctx, upsert, uuid.Must(uuid.NewV7()), source.TenantID, source.AgentID,
			source.Key, source.Engine, source.EngineVersion).Scan(&sourceID)
		if err != nil {
			return err
		}
		return replaceCapabilities(ctx, tx, source.TenantID, sourceID, source.Capabilities)
	})
	if err != nil {
		return uuid.Nil, storageError("upsert source", err)
	}
	return sourceID, nil
}

// replaceCapabilities deletes through the row policy, so stale capabilities do
// not linger after an upgrade or a configuration change.
func replaceCapabilities(ctx context.Context, tx pgx.Tx, tenantID, sourceID uuid.UUID, capabilities []fleet.Capability) error {
	if _, err := tx.Exec(ctx, `DELETE FROM source_capabilities WHERE source_id = $1`, sourceID); err != nil {
		return err
	}
	batch := &pgx.Batch{}
	const insert = `INSERT INTO source_capabilities (tenant_id, source_id, capability, support, reason_code)
		VALUES ($1, $2, $3, $4, $5)`
	for _, capability := range capabilities {
		batch.Queue(insert, tenantID, sourceID, capability.Capability, capability.Support, capability.ReasonCode)
	}
	return tx.SendBatch(ctx, batch).Close()
}

func (s *Store) ListSources(ctx context.Context, tenantID uuid.UUID) ([]fleet.Source, error) {
	var sources []fleet.Source
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const query = `SELECT id, tenant_id, agent_id, source_key, engine, engine_version, updated_at
			FROM sources ORDER BY source_key`
		rows, err := tx.Query(ctx, query)
		if err != nil {
			return err
		}
		sources, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (fleet.Source, error) {
			var item fleet.Source
			err := row.Scan(&item.ID, &item.TenantID, &item.AgentID, &item.Key, &item.Engine, &item.EngineVersion, &item.UpdatedAt)
			return item, err
		})
		if err != nil {
			return err
		}
		return attachCapabilities(ctx, tx, sources)
	})
	if err != nil {
		return nil, storageError("list sources", err)
	}
	return sources, nil
}

func attachCapabilities(ctx context.Context, tx pgx.Tx, sources []fleet.Source) error {
	byID := make(map[uuid.UUID]*fleet.Source, len(sources))
	for i := range sources {
		byID[sources[i].ID] = &sources[i]
	}
	rows, err := tx.Query(ctx, `SELECT source_id, capability, support, reason_code FROM source_capabilities ORDER BY capability`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var sourceID uuid.UUID
		var capability fleet.Capability
		if err := rows.Scan(&sourceID, &capability.Capability, &capability.Support, &capability.ReasonCode); err != nil {
			return err
		}
		if source, ok := byID[sourceID]; ok {
			source.Capabilities = append(source.Capabilities, capability)
		}
	}
	return rows.Err()
}
