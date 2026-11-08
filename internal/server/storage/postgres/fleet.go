package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"dataguard/internal/contract/codes"
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
		const insert = `INSERT INTO agents (id, tenant_id, environment_id, status, version, certificate_expires, created_at, sealing_public_key)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
		_, err := tx.Exec(ctx, insert, agent.ID, agent.TenantID, agent.EnvironmentID, agent.Status,
			agent.Version, agent.CertificateExpires, agent.CreatedAt, agent.SealingPublicKey)
		return err
	})
	if err != nil {
		return storageError("create agent", err)
	}
	return nil
}

const agentColumns = `id, tenant_id, environment_id, status, version, certificate_expires, last_seen_at, created_at, sealing_public_key`

func scanAgent(row pgx.Row) (fleet.Agent, error) {
	var agent fleet.Agent
	err := row.Scan(&agent.ID, &agent.TenantID, &agent.EnvironmentID, &agent.Status, &agent.Version,
		&agent.CertificateExpires, &agent.LastSeenAt, &agent.CreatedAt, &agent.SealingPublicKey)
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

func (s *Store) TouchAgent(ctx context.Context, tenantID, agentID uuid.UUID, version string) (uint64, error) {
	var sourcesVersion uint64
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const update = `UPDATE agents SET last_seen_at = now(), version = $2 WHERE id = $1 RETURNING sources_version`
		return tx.QueryRow(ctx, update, agentID, version).Scan(&sourcesVersion)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, fleet.ErrNotFound
	}
	if err != nil {
		return 0, storageError("touch agent", err)
	}
	return sourcesVersion, nil
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

const sourceColumns = `id, tenant_id, agent_id, source_key, engine, host, port, database_name, username,
	tls_mode, audit_directory, max_connections, sealed_password, engine_version, status_code, probed_at, updated_at, draft`

func scanSource(row pgx.Row) (fleet.Source, error) {
	var item fleet.Source
	err := row.Scan(&item.ID, &item.TenantID, &item.AgentID, &item.Key, &item.Engine, &item.Host, &item.Port,
		&item.Database, &item.Username, &item.TLS, &item.AuditDirectory, &item.MaxConnections, &item.SealedPassword,
		&item.EngineVersion, &item.StatusCode, &item.ProbedAt, &item.UpdatedAt, &item.Draft)
	return item, err
}

// staleDraft is the age past which a draft left behind by a closed browser is
// removed, the next time a source is added to its agent. A check takes
// seconds; an hour is plenty for someone who stepped away.
const staleDraft = time.Hour

// bumpSourcesVersion makes the agent fetch its list again. Callers run it in
// the transaction that changed the list.
func bumpSourcesVersion(ctx context.Context, tx pgx.Tx, agentID uuid.UUID) error {
	_, err := tx.Exec(ctx, `UPDATE agents SET sources_version = sources_version + 1 WHERE id = $1`, agentID)
	return err
}

func (s *Store) CreateSource(ctx context.Context, source fleet.Source) error {
	err := s.inTenant(ctx, source.TenantID, func(tx pgx.Tx) error {
		// Drafts nobody saved or cancelled leave the agent's list here, in the
		// same version bump, and free their names.
		const sweep = `UPDATE sources SET deleted_at = now(), sealed_password = NULL
			WHERE agent_id = $1 AND draft AND deleted_at IS NULL AND updated_at < now() - $2::interval`
		if _, err := tx.Exec(ctx, sweep, source.AgentID, staleDraft.String()); err != nil {
			return err
		}
		const insert = `INSERT INTO sources (id, tenant_id, agent_id, source_key, engine, host, port, database_name,
				username, tls_mode, audit_directory, max_connections, sealed_password, draft)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`
		if _, err := tx.Exec(ctx, insert, source.ID, source.TenantID, source.AgentID, source.Key, source.Engine,
			source.Host, source.Port, source.Database, source.Username, source.TLS, source.AuditDirectory,
			source.MaxConnections, source.SealedPassword, source.Draft); err != nil {
			return err
		}
		return bumpSourcesVersion(ctx, tx, source.AgentID)
	})
	return sourceWriteError("create source", err)
}

func (s *Store) ActivateSource(ctx context.Context, tenantID, sourceID uuid.UUID) error {
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var agentID uuid.UUID
		var draft bool
		const read = `SELECT agent_id, draft FROM sources WHERE id = $1 AND deleted_at IS NULL FOR UPDATE`
		if err := tx.QueryRow(ctx, read, sourceID).Scan(&agentID, &draft); err != nil {
			return err
		}
		if !draft {
			return nil
		}
		// The probe is reset as on any change: a new one means the agent holds
		// the saved source and will take its scans, not only the draft.
		const activate = `UPDATE sources SET draft = false, updated_at = now(), status_code = '', probed_at = NULL WHERE id = $1`
		if _, err := tx.Exec(ctx, activate, sourceID); err != nil {
			return err
		}
		return bumpSourcesVersion(ctx, tx, agentID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return fleet.ErrNotFound
	}
	return sourceWriteError("activate source", err)
}

func (s *Store) UpdateSource(ctx context.Context, source fleet.Source) error {
	err := s.inTenant(ctx, source.TenantID, func(tx pgx.Tx) error {
		const update = `UPDATE sources SET source_key = $2, host = $3, port = $4, database_name = $5, username = $6,
				tls_mode = $7, audit_directory = $8, max_connections = $9, sealed_password = $10, updated_at = now(),
				status_code = '', probed_at = NULL
			WHERE id = $1 AND deleted_at IS NULL`
		result, err := tx.Exec(ctx, update, source.ID, source.Key, source.Host, source.Port, source.Database,
			source.Username, source.TLS, source.AuditDirectory, source.MaxConnections, source.SealedPassword)
		if err != nil {
			return err
		}
		if result.RowsAffected() == 0 {
			return fleet.ErrNotFound
		}
		return bumpSourcesVersion(ctx, tx, source.AgentID)
	})
	return sourceWriteError("update source", err)
}

func (s *Store) DeleteSource(ctx context.Context, tenantID, sourceID uuid.UUID) error {
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var agentID uuid.UUID
		const remove = `UPDATE sources SET deleted_at = now(), sealed_password = NULL
			WHERE id = $1 AND deleted_at IS NULL RETURNING agent_id`
		if err := tx.QueryRow(ctx, remove, sourceID).Scan(&agentID); err != nil {
			return err
		}
		const cancel = `UPDATE scan_jobs SET status = 'cancelled', failure_code = $2, finished_at = now()
			WHERE source_id = $1 AND status IN ('pending', 'running')`
		if _, err := tx.Exec(ctx, cancel, sourceID, codes.SourceDeleted); err != nil {
			return err
		}
		return bumpSourcesVersion(ctx, tx, agentID)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return fleet.ErrNotFound
	}
	return sourceWriteError("delete source", err)
}

func sourceWriteError(op string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fleet.ErrNotFound):
		return err
	case isUniqueViolation(err):
		return fleet.ErrConflict
	default:
		return storageError(op, err)
	}
}

func (s *Store) GetSource(ctx context.Context, tenantID, sourceID uuid.UUID) (fleet.Source, error) {
	var source fleet.Source
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		source, err = scanSource(tx.QueryRow(ctx, `SELECT `+sourceColumns+` FROM sources WHERE id = $1 AND deleted_at IS NULL`, sourceID))
		if err != nil {
			return err
		}
		one := []fleet.Source{source}
		if err := attachCapabilities(ctx, tx, one); err != nil {
			return err
		}
		source = one[0]
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return fleet.Source{}, fleet.ErrNotFound
	}
	if err != nil {
		return fleet.Source{}, storageError("get source", err)
	}
	return source, nil
}

func (s *Store) ListSources(ctx context.Context, tenantID uuid.UUID) ([]fleet.Source, error) {
	var sources []fleet.Source
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		sources, err = querySources(ctx, tx, `SELECT `+sourceColumns+` FROM sources WHERE deleted_at IS NULL AND NOT draft ORDER BY source_key`)
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

func (s *Store) AgentSourceList(ctx context.Context, tenantID, agentID uuid.UUID) (uint64, []fleet.Source, error) {
	var version uint64
	var sources []fleet.Source
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// The version is read first and under a share lock, so a concurrent change
		// either lands in this list or advances the version past it.
		if err := tx.QueryRow(ctx, `SELECT sources_version FROM agents WHERE id = $1 FOR SHARE`, agentID).Scan(&version); err != nil {
			return err
		}
		var err error
		sources, err = querySources(ctx, tx, `SELECT `+sourceColumns+` FROM sources
			WHERE agent_id = $1 AND deleted_at IS NULL ORDER BY id`, agentID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil, fleet.ErrNotFound
	}
	if err != nil {
		return 0, nil, storageError("agent source list", err)
	}
	return version, sources, nil
}

func querySources(ctx context.Context, tx pgx.Tx, query string, args ...any) ([]fleet.Source, error) {
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (fleet.Source, error) {
		return scanSource(row)
	})
}

func (s *Store) RecordProbes(ctx context.Context, tenantID, agentID uuid.UUID, probes []fleet.Probe) error {
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for _, probe := range probes {
			const update = `UPDATE sources SET engine_version = $3, status_code = $4, probed_at = now()
				WHERE id = $1 AND agent_id = $2 AND deleted_at IS NULL`
			result, err := tx.Exec(ctx, update, probe.SourceID, agentID, probe.EngineVersion, probe.StatusCode)
			if err != nil {
				return err
			}
			if result.RowsAffected() == 0 {
				continue
			}
			if err := replaceCapabilities(ctx, tx, tenantID, probe.SourceID, probe.Capabilities); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return storageError("record probes", err)
	}
	return nil
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
