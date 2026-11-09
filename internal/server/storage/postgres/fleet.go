package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"dataguard/internal/contract/codes"
	"dataguard/internal/core/fleet"
	"dataguard/internal/core/oplog"
)

func (s *Store) CreateEnrollmentToken(ctx context.Context, tenantID, environmentID uuid.UUID, hash []byte, expiresAt time.Time, entry oplog.Entry) error {
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var exists bool
		const check = `SELECT EXISTS (SELECT 1 FROM environments WHERE id = $1)`
		if err := tx.QueryRow(ctx, check, environmentID).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fleet.ErrNotFound
		}
		const insert = `INSERT INTO enrollment_tokens (id, tenant_id, environment_id, token_hash, expires_at, created_by_subject, created_by_name)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`
		if _, err := tx.Exec(ctx, insert, uuid.Must(uuid.NewV7()), tenantID, environmentID, hash, expiresAt,
			entry.Actor.Subject, entry.Actor.Name); err != nil {
			return err
		}
		return recordAction(ctx, tx, tenantID, entry)
	})
	return writeError("create enrollment token", err, fleet.ErrNotFound)
}

func (s *Store) ConsumeEnrollmentToken(ctx context.Context, tenantID uuid.UUID, hash []byte) (uuid.UUID, oplog.Actor, error) {
	var environmentID uuid.UUID
	var issuer oplog.Actor
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const consume = `UPDATE enrollment_tokens SET used_at = now()
			WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
			RETURNING environment_id, created_by_subject, created_by_name`
		return tx.QueryRow(ctx, consume, hash).Scan(&environmentID, &issuer.Subject, &issuer.Name)
	})
	if err := readError("consume enrollment token", err, fleet.ErrInvalidToken); err != nil {
		return uuid.Nil, oplog.Actor{}, err
	}
	return environmentID, issuer, nil
}

func (s *Store) CreateAgent(ctx context.Context, agent fleet.Agent, entry oplog.Entry) error {
	err := s.inTenant(ctx, agent.TenantID, func(tx pgx.Tx) error {
		const insert = `INSERT INTO agents (id, tenant_id, environment_id, status, version, certificate_expires, created_at, sealing_public_key)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
		if _, err := tx.Exec(ctx, insert, agent.ID, agent.TenantID, agent.EnvironmentID, agent.Status,
			agent.Version, agent.CertificateExpires, agent.CreatedAt, agent.SealingPublicKey); err != nil {
			return err
		}
		return recordAction(ctx, tx, agent.TenantID, entry)
	})
	if err != nil {
		return storageError("create agent", err)
	}
	return nil
}

const agentColumns = `id, tenant_id, environment_id, status, version, certificate_expires, last_seen_at, created_at,
	sealing_public_key, contract_version, refused_contract_version, policy_key_epoch`

func scanAgent(row pgx.Row, agent *fleet.Agent) error {
	return row.Scan(&agent.ID, &agent.TenantID, &agent.EnvironmentID, &agent.Status, &agent.Version,
		&agent.CertificateExpires, &agent.LastSeenAt, &agent.CreatedAt, &agent.SealingPublicKey,
		&agent.ContractVersion, &agent.RefusedContractVersion, &agent.PolicyKeyEpoch)
}

func (s *Store) GetAgent(ctx context.Context, tenantID, agentID uuid.UUID) (fleet.Agent, error) {
	var agent fleet.Agent
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return scanAgent(tx.QueryRow(ctx, `SELECT `+agentColumns+` FROM agents WHERE id = $1`, agentID), &agent)
	})
	if err := readError("get agent", err, fleet.ErrNotFound); err != nil {
		return fleet.Agent{}, err
	}
	return agent, nil
}

func (s *Store) ListAgents(ctx context.Context, tenantID uuid.UUID) ([]fleet.Agent, error) {
	var agents []fleet.Agent
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		agents, err = queryAll(ctx, tx, scanAgent, `SELECT `+agentColumns+` FROM agents ORDER BY created_at DESC`)
		return err
	})
	if err != nil {
		return nil, storageError("list agents", err)
	}
	return agents, nil
}

func (s *Store) TouchAgent(ctx context.Context, tenantID, agentID uuid.UUID, beat fleet.Heartbeat) (uint64, error) {
	var sourcesVersion uint64
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const update = `UPDATE agents SET last_seen_at = now(), version = $2, contract_version = $3, refused_contract_version = NULL,
				policy_key_epoch = $4,
				sources_version = CASE WHEN $5 > sources_version THEN $5 + 1 ELSE sources_version END
			WHERE id = $1 RETURNING sources_version`
		return tx.QueryRow(ctx, update, agentID, beat.Version, beat.Contract, beat.PolicyKeyEpoch, int64(beat.AppliedSourcesVersion)).Scan(&sourcesVersion)
	})
	if err := readError("touch agent", err, fleet.ErrNotFound); err != nil {
		return 0, err
	}
	return sourcesVersion, nil
}

func (s *Store) RefuseContract(ctx context.Context, tenantID, agentID uuid.UUID, offered uint32) error {
	const update = `UPDATE agents SET refused_contract_version = $2 WHERE id = $1`
	return s.updateAgent(ctx, tenantID, "refuse contract", update, agentID, offered)
}

func (s *Store) RevokeAgent(ctx context.Context, tenantID, agentID uuid.UUID, entry oplog.Entry) error {
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var status string
		if err := tx.QueryRow(ctx, `SELECT status FROM agents WHERE id = $1 FOR UPDATE`, agentID).Scan(&status); err != nil {
			return err
		}
		// Revoking a revoked agent changes nothing, so the journal gets nothing.
		if status == fleet.StatusRevoked {
			return nil
		}
		const update = `UPDATE agents SET status = 'revoked', revoked_at = now() WHERE id = $1`
		if _, err := tx.Exec(ctx, update, agentID); err != nil {
			return err
		}
		return recordAction(ctx, tx, tenantID, entry)
	})
	return readError("revoke agent", err, fleet.ErrNotFound)
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
	return writeError(op, err, fleet.ErrNotFound)
}

const sourceColumns = `id, tenant_id, agent_id, source_key, engine, host, port, database_name, username,
	tls_mode, audit_directory, max_connections, sealed_password, engine_version, status_code, probed_at, updated_at, draft`

func scanSource(row pgx.Row, item *fleet.Source) error {
	return row.Scan(&item.ID, &item.TenantID, &item.AgentID, &item.Key, &item.Engine, &item.Host, &item.Port,
		&item.Database, &item.Username, &item.TLS, &item.AuditDirectory, &item.MaxConnections, &item.SealedPassword,
		&item.EngineVersion, &item.StatusCode, &item.ProbedAt, &item.UpdatedAt, &item.Draft)
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

// recordIf writes entry when the change is one the journal records.
func recordIf(ctx context.Context, tx pgx.Tx, tenantID uuid.UUID, entry *oplog.Entry) error {
	if entry == nil {
		return nil
	}
	return recordAction(ctx, tx, tenantID, *entry)
}

func (s *Store) CreateSource(ctx context.Context, source fleet.Source, entry *oplog.Entry) error {
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
		if err := recordIf(ctx, tx, source.TenantID, entry); err != nil {
			return err
		}
		return bumpSourcesVersion(ctx, tx, source.AgentID)
	})
	return sourceWriteError("create source", err)
}

func (s *Store) ActivateSource(ctx context.Context, tenantID, sourceID uuid.UUID, entry oplog.Entry) error {
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
		if err := recordAction(ctx, tx, tenantID, entry); err != nil {
			return err
		}
		return bumpSourcesVersion(ctx, tx, agentID)
	})
	return sourceWriteError("activate source", err)
}

func (s *Store) UpdateSource(ctx context.Context, source fleet.Source, entry *oplog.Entry) error {
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
		if err := recordIf(ctx, tx, source.TenantID, entry); err != nil {
			return err
		}
		return bumpSourcesVersion(ctx, tx, source.AgentID)
	})
	return sourceWriteError("update source", err)
}

func (s *Store) DeleteSource(ctx context.Context, tenantID, sourceID uuid.UUID, entry *oplog.Entry) error {
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
		if err := recordIf(ctx, tx, tenantID, entry); err != nil {
			return err
		}
		return bumpSourcesVersion(ctx, tx, agentID)
	})
	return sourceWriteError("delete source", err)
}

func sourceWriteError(op string, err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, fleet.ErrNotFound):
		return err
	case errors.Is(err, pgx.ErrNoRows):
		return fleet.ErrNotFound
	case isUniqueViolation(err):
		return fleet.ErrConflict
	default:
		return storageError(op, err)
	}
}

func (s *Store) GetSource(ctx context.Context, tenantID, sourceID uuid.UUID) (fleet.Source, error) {
	var source fleet.Source
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		one := make([]fleet.Source, 1)
		if err := scanSource(tx.QueryRow(ctx, `SELECT `+sourceColumns+` FROM sources WHERE id = $1 AND deleted_at IS NULL`, sourceID), &one[0]); err != nil {
			return err
		}
		if err := attachCapabilities(ctx, tx, one); err != nil {
			return err
		}
		source = one[0]
		return nil
	})
	if err := readError("get source", err, fleet.ErrNotFound); err != nil {
		return fleet.Source{}, err
	}
	return source, nil
}

func (s *Store) ListSources(ctx context.Context, tenantID uuid.UUID) ([]fleet.Source, error) {
	var sources []fleet.Source
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		sources, err = queryAll(ctx, tx, scanSource, `SELECT `+sourceColumns+` FROM sources WHERE deleted_at IS NULL AND NOT draft ORDER BY source_key`)
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
		sources, err = queryAll(ctx, tx, scanSource, `SELECT `+sourceColumns+` FROM sources
			WHERE agent_id = $1 AND deleted_at IS NULL ORDER BY id`, agentID)
		return err
	})
	if err := readError("agent source list", err, fleet.ErrNotFound); err != nil {
		return 0, nil, err
	}
	return version, sources, nil
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
