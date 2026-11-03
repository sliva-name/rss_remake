package postgres

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"dataguard/internal/core/audit"
	"dataguard/internal/core/coverage"
)

// AgentSources lists sources an agent reported.
func (s *Store) AgentSources(ctx context.Context, tenantID, agentID uuid.UUID) ([]uuid.UUID, error) {
	var sources []uuid.UUID
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM sources WHERE agent_id = $1`, agentID)
		if err != nil {
			return err
		}
		sources, err = pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
		return err
	})
	if err != nil {
		return nil, storageError("list agent sources", err)
	}
	return sources, nil
}

// ColumnsOf returns active columns with their detected categories.
func (s *Store) ColumnsOf(ctx context.Context, tenantID, sourceID uuid.UUID) (map[audit.ColumnKey]audit.ColumnInfo, error) {
	columns := map[audit.ColumnKey]audit.ColumnInfo{}
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const query = `SELECT t.database_name, t.schema_name, t.table_name, ac.column_name, ac.id,
				COALESCE(array_agg(c.category_id) FILTER (WHERE c.status = 'detected'), '{}')
			FROM asset_tables t
			JOIN asset_columns ac ON ac.table_id = t.id AND ac.status = 'active'
			LEFT JOIN classifications c ON c.column_id = ac.id
			WHERE t.source_id = $1 AND t.status = 'active'
			GROUP BY t.database_name, t.schema_name, t.table_name, ac.column_name, ac.id`
		rows, err := tx.Query(ctx, query, sourceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var key audit.ColumnKey
			var info audit.ColumnInfo
			if err := rows.Scan(&key.Database, &key.Schema, &key.Table, &key.Column, &info.ID, &info.Categories); err != nil {
				return err
			}
			columns[key] = info
		}
		return rows.Err()
	})
	if err != nil {
		return nil, storageError("read source columns", err)
	}
	return columns, nil
}

// CatalogVersion is the finish time of the latest applied scan of a source.
func (s *Store) CatalogVersion(ctx context.Context, tenantID, sourceID uuid.UUID) (time.Time, error) {
	var version *time.Time
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const query = `SELECT max(finished_at) FROM scan_jobs WHERE source_id = $1 AND status IN ('completed', 'partial')`
		return tx.QueryRow(ctx, query, sourceID).Scan(&version)
	})
	if err != nil {
		return time.Time{}, storageError("read catalog version", err)
	}
	if version == nil {
		return time.Time{}, nil
	}
	return *version, nil
}

// SaveHealth records collector reports. Sources not owned by the agent are skipped
// by the join, so a client cannot write health for someone else's source.
func (s *Store) SaveHealth(ctx context.Context, tenantID, agentID uuid.UUID, reports []coverage.Health) error {
	if len(reports) == 0 {
		return nil
	}
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		for i := range reports {
			report := &reports[i]
			const upsert = `INSERT INTO source_audit_health
					(tenant_id, source_id, state, reason_code, position_read_at, lost_events_total, reported_at)
				SELECT $1, id, $3, $4, $5, $6, $7 FROM sources WHERE id = $2 AND agent_id = $8
				ON CONFLICT (source_id) DO UPDATE SET state = EXCLUDED.state, reason_code = EXCLUDED.reason_code,
					position_read_at = EXCLUDED.position_read_at, lost_events_total = EXCLUDED.lost_events_total,
					reported_at = EXCLUDED.reported_at`
			if _, err := tx.Exec(ctx, upsert, tenantID, report.SourceID, report.State, report.ReasonCode,
				report.PositionReadAt, report.LostEvents, report.ReportedAt, agentID); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return storageError("save audit health", err)
	}
	return nil
}

// HealthReports returns the last report of every source.
func (s *Store) HealthReports(ctx context.Context, tenantID uuid.UUID) ([]coverage.Health, error) {
	var reports []coverage.Health
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const query = `SELECT source_id, state, reason_code, position_read_at, lost_events_total, reported_at FROM source_audit_health`
		rows, err := tx.Query(ctx, query)
		if err != nil {
			return err
		}
		reports, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (coverage.Health, error) {
			var item coverage.Health
			err := row.Scan(&item.SourceID, &item.State, &item.ReasonCode, &item.PositionReadAt, &item.LostEvents, &item.ReportedAt)
			return item, err
		})
		return err
	})
	if err != nil {
		return nil, storageError("read audit health", err)
	}
	return reports, nil
}

// LatestScans returns the newest finished scan per source.
func (s *Store) LatestScans(ctx context.Context, tenantID uuid.UUID) (map[uuid.UUID]coverage.ScanState, error) {
	scans := map[uuid.UUID]coverage.ScanState{}
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const query = `SELECT DISTINCT ON (source_id) source_id, status, finished_at
			FROM scan_jobs WHERE finished_at IS NOT NULL ORDER BY source_id, finished_at DESC`
		rows, err := tx.Query(ctx, query)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sourceID uuid.UUID
			var state coverage.ScanState
			var finished time.Time
			if err := rows.Scan(&sourceID, &state.Status, &finished); err != nil {
				return err
			}
			state.FinishedAt = &finished
			scans[sourceID] = state
		}
		return rows.Err()
	})
	if err != nil {
		return nil, storageError("read latest scans", err)
	}
	return scans, nil
}
