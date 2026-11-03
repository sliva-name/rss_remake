package postgres

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"dataguard/internal/contract/codes"
	"dataguard/internal/core/asset"
	"dataguard/internal/core/scan"
)

func (s *Store) SourceExists(ctx context.Context, tenantID, sourceID uuid.UUID) (bool, error) {
	var exists bool
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM sources WHERE id = $1 AND deleted_at IS NULL)`, sourceID).Scan(&exists)
	})
	if err != nil {
		return false, storageError("check source", err)
	}
	return exists, nil
}

func (s *Store) CreateJob(ctx context.Context, job scan.Job) error {
	err := s.inTenant(ctx, job.TenantID, func(tx pgx.Tx) error {
		const insert = `INSERT INTO scan_jobs (id, tenant_id, source_id, status, requested_by, created_at)
			VALUES ($1, $2, $3, $4, $5, $6)`
		_, err := tx.Exec(ctx, insert, job.ID, job.TenantID, job.SourceID, job.Status, job.RequestedBy, job.CreatedAt)
		return err
	})
	if err != nil {
		return storageError("create scan job", err)
	}
	return nil
}

const jobColumns = `id, tenant_id, source_id, status, requested_by, failure_code, created_at, started_at, finished_at`

func collectJobs(rows pgx.Rows) ([]scan.Job, error) {
	return pgx.CollectRows(rows, func(row pgx.CollectableRow) (scan.Job, error) {
		var job scan.Job
		err := row.Scan(&job.ID, &job.TenantID, &job.SourceID, &job.Status, &job.RequestedBy, &job.FailureCode,
			&job.CreatedAt, &job.StartedAt, &job.FinishedAt)
		return job, err
	})
}

func (s *Store) ListJobs(ctx context.Context, tenantID uuid.UUID, limit int) ([]scan.Job, error) {
	var jobs []scan.Job
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+jobColumns+` FROM scan_jobs ORDER BY created_at DESC LIMIT $1`, limit)
		if err != nil {
			return err
		}
		jobs, err = collectJobs(rows)
		return err
	})
	if err != nil {
		return nil, storageError("list scan jobs", err)
	}
	return jobs, nil
}

func (s *Store) LeaseJobs(ctx context.Context, tenantID, agentID uuid.UUID, maxJobs int) ([]scan.Job, error) {
	var jobs []scan.Job
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// A job whose agent vanished comes back through an expired lease; after
		// MaxAttempts it fails instead of being retried forever.
		const giveUp = `UPDATE scan_jobs SET status = 'failed', failure_code = $2, finished_at = now()
			WHERE status = 'running' AND lease_until < now() AND attempts >= $1`
		if _, err := tx.Exec(ctx, giveUp, scan.MaxAttempts, codes.LeaseExpired); err != nil {
			return err
		}
		const lease = `UPDATE scan_jobs SET status = 'running', attempts = attempts + 1,
				lease_until = now() + make_interval(secs => $1), started_at = COALESCE(started_at, now())
			WHERE id IN (
				SELECT j.id FROM scan_jobs j JOIN sources src ON src.id = j.source_id
				WHERE src.agent_id = $2 AND src.deleted_at IS NULL
				  AND (j.status = 'pending' OR (j.status = 'running' AND j.lease_until < now()))
				ORDER BY j.created_at
				LIMIT $3 FOR UPDATE OF j SKIP LOCKED)
			RETURNING ` + jobColumns
		rows, err := tx.Query(ctx, lease, scan.LeaseDuration.Seconds(), agentID, maxJobs)
		if err != nil {
			return err
		}
		jobs, err = collectJobs(rows)
		return err
	})
	if err != nil {
		return nil, storageError("lease scan jobs", err)
	}
	return jobs, nil
}

func (s *Store) Complete(ctx context.Context, tenantID, agentID, jobID uuid.UUID, build func([]asset.Table) (scan.Outcome, error)) error {
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		sourceID, err := lockRunningJob(ctx, tx, jobID, agentID)
		if err != nil {
			return err
		}
		existing, err := loadTables(ctx, tx, sourceID)
		if err != nil {
			return err
		}
		outcome, err := build(existing)
		if err != nil {
			return err
		}
		return persistOutcome(ctx, tx, tenantID, sourceID, jobID, outcome)
	})
	if errors.Is(err, scan.ErrStale) {
		return err
	}
	if err != nil {
		return storageError("complete scan job", err)
	}
	return nil
}

// lockRunningJob serializes completion, and rejects a late or duplicate result
// so a retried submission cannot apply a snapshot twice.
func lockRunningJob(ctx context.Context, tx pgx.Tx, jobID, agentID uuid.UUID) (uuid.UUID, error) {
	const query = `SELECT j.source_id FROM scan_jobs j JOIN sources src ON src.id = j.source_id
		WHERE j.id = $1 AND j.status = 'running' AND src.agent_id = $2 FOR UPDATE OF j`
	var sourceID uuid.UUID
	err := tx.QueryRow(ctx, query, jobID, agentID).Scan(&sourceID)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, scan.ErrStale
	}
	return sourceID, err
}

func loadTables(ctx context.Context, tx pgx.Tx, sourceID uuid.UUID) ([]asset.Table, error) {
	const tablesQuery = `SELECT DISTINCT ON (database_name, schema_name, table_name)
			id, database_name, schema_name, table_name, kind, fingerprint, status
		FROM asset_tables WHERE source_id = $1
		ORDER BY database_name, schema_name, table_name, last_seen_at DESC`
	rows, err := tx.Query(ctx, tablesQuery, sourceID)
	if err != nil {
		return nil, err
	}
	tables, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (asset.Table, error) {
		var table asset.Table
		err := row.Scan(&table.ID, &table.Database, &table.Schema, &table.Name, &table.Kind, &table.Fingerprint, &table.Status)
		return table, err
	})
	if err != nil {
		return nil, err
	}
	byID := make(map[uuid.UUID]*asset.Table, len(tables))
	ids := make([]uuid.UUID, 0, len(tables))
	for i := range tables {
		byID[tables[i].ID] = &tables[i]
		ids = append(ids, tables[i].ID)
	}
	const columnsQuery = `SELECT table_id, id, column_name, native_type, ordinal, nullable, status
		FROM asset_columns WHERE table_id = ANY($1) ORDER BY ordinal`
	columnRows, err := tx.Query(ctx, columnsQuery, ids)
	if err != nil {
		return nil, err
	}
	defer columnRows.Close()
	for columnRows.Next() {
		var tableID uuid.UUID
		var column asset.Column
		if err := columnRows.Scan(&tableID, &column.ID, &column.Name, &column.NativeType, &column.Ordinal, &column.Nullable, &column.Status); err != nil {
			return nil, err
		}
		if table, ok := byID[tableID]; ok {
			table.Columns = append(table.Columns, column)
		}
	}
	return tables, columnRows.Err()
}

func persistOutcome(ctx context.Context, tx pgx.Tx, tenantID, sourceID, jobID uuid.UUID, outcome scan.Outcome) error {
	now := time.Now().UTC()
	if err := persistPlan(ctx, tx, tenantID, sourceID, jobID, outcome.Plan, now); err != nil {
		return err
	}
	if err := persistClassifications(ctx, tx, tenantID, jobID, outcome, now); err != nil {
		return err
	}
	for _, skipped := range outcome.Result.GetSkippedTables() {
		path := skipped.GetTable()
		const insert = `INSERT INTO scan_skipped_tables (tenant_id, job_id, database_name, schema_name, table_name, reason_code)
			VALUES ($1, $2, $3, $4, $5, $6)`
		if _, err := tx.Exec(ctx, insert, tenantID, jobID, path.GetDatabase(), path.GetSchema(), path.GetTable(), skipped.GetReasonCode()); err != nil {
			return err
		}
	}
	const finish = `UPDATE scan_jobs SET status = $2, failure_code = $3, finished_at = now(), lease_until = NULL WHERE id = $1`
	_, err := tx.Exec(ctx, finish, jobID, outcome.Status, outcome.FailureCode)
	return err
}

func persistPlan(ctx context.Context, tx pgx.Tx, tenantID, sourceID, jobID uuid.UUID, plan asset.Plan, now time.Time) error {
	for i := range plan.Tables {
		if err := persistTable(ctx, tx, tenantID, sourceID, &plan.Tables[i], now); err != nil {
			return err
		}
	}
	for _, rename := range plan.Renames {
		const insert = `INSERT INTO asset_renames (tenant_id, object_kind, object_id, old_name, new_name, detected_at, detected_by)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`
		if _, err := tx.Exec(ctx, insert, tenantID, rename.ObjectKind, rename.ObjectID, rename.OldName, rename.NewName, now, rename.DetectedBy); err != nil {
			return err
		}
	}
	for _, change := range plan.Changes {
		if err := recordChange(ctx, tx, tenantID, jobID, change.Kind, change.TableID, change.ColumnID, "", now); err != nil {
			return err
		}
	}
	return nil
}

func recordChange(ctx context.Context, tx pgx.Tx, tenantID, jobID uuid.UUID, kind string, tableID uuid.UUID, columnID *uuid.UUID, category string, now time.Time) error {
	const insert = `INSERT INTO catalog_changes (tenant_id, occurred_at, job_id, kind, table_id, column_id, category_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`
	_, err := tx.Exec(ctx, insert, tenantID, now, jobID, kind, tableID, columnID, category)
	return err
}

func persistTable(ctx context.Context, tx pgx.Tx, tenantID, sourceID uuid.UUID, table *asset.Table, now time.Time) error {
	const upsertTable = `INSERT INTO asset_tables
			(id, tenant_id, source_id, database_name, schema_name, table_name, kind, fingerprint, status, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $10)
		ON CONFLICT (id) DO UPDATE SET table_name = EXCLUDED.table_name, kind = EXCLUDED.kind,
			fingerprint = EXCLUDED.fingerprint, status = EXCLUDED.status,
			last_seen_at = CASE WHEN EXCLUDED.status = 'active' THEN EXCLUDED.last_seen_at ELSE asset_tables.last_seen_at END`
	if _, err := tx.Exec(ctx, upsertTable, table.ID, tenantID, sourceID, table.Database, table.Schema, table.Name,
		table.Kind, table.Fingerprint, table.Status, now); err != nil {
		return err
	}
	// Removals first: a renamed column may take over a name that is still marked
	// active in the partial unique index until its old owner is updated.
	ordered := slices.Clone(table.Columns)
	slices.SortStableFunc(ordered, func(a, b asset.Column) int {
		if a.Status == b.Status {
			return 0
		}
		if a.Status == asset.StatusRemoved {
			return -1
		}
		return 1
	})
	const upsertColumn = `INSERT INTO asset_columns
			(id, tenant_id, table_id, column_name, native_type, ordinal, nullable, status, first_seen_at, last_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $9)
		ON CONFLICT (id) DO UPDATE SET column_name = EXCLUDED.column_name, native_type = EXCLUDED.native_type,
			ordinal = EXCLUDED.ordinal, nullable = EXCLUDED.nullable, status = EXCLUDED.status,
			last_seen_at = CASE WHEN EXCLUDED.status = 'active' THEN EXCLUDED.last_seen_at ELSE asset_columns.last_seen_at END`
	for _, column := range ordered {
		if _, err := tx.Exec(ctx, upsertColumn, column.ID, tenantID, table.ID, column.Name, column.NativeType,
			column.Ordinal, column.Nullable, column.Status, now); err != nil {
			return err
		}
	}
	return nil
}

func persistClassifications(ctx context.Context, tx pgx.Tx, tenantID, jobID uuid.UUID, outcome scan.Outcome, now time.Time) error {
	detected := make(map[columnCategory]bool, len(outcome.Classifications))
	for _, item := range outcome.Classifications {
		detected[columnCategory{item.ColumnID, item.Item.GetCategoryId()}] = true
		if err := upsertClassification(ctx, tx, tenantID, jobID, item, now); err != nil {
			return err
		}
	}
	return clearStale(ctx, tx, tenantID, jobID, outcome.ProfiledTables, detected, now)
}

type columnCategory struct {
	columnID uuid.UUID
	category string
}

func upsertClassification(ctx context.Context, tx pgx.Tx, tenantID, jobID uuid.UUID, item scan.Classification, now time.Time) error {
	finding, evidence, profile := item.Item, item.Item.GetEvidence(), item.Item.GetProfile()
	var checksum *float64
	if evidence.ChecksumValidRatio != nil {
		checksum = evidence.ChecksumValidRatio
	}
	const upsert = `INSERT INTO classifications (tenant_id, column_id, category_id, status, confidence, name_match,
			context_match, format_ratio, checksum_ratio, rows_inspected, rows_non_null, rows_matched,
			unique_estimate, sampling_method, first_seen_at, updated_at)
		VALUES ($1, $2, $3, 'detected', $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14)
		ON CONFLICT (column_id, category_id) DO UPDATE SET status = 'detected', confidence = EXCLUDED.confidence,
			name_match = EXCLUDED.name_match, context_match = EXCLUDED.context_match,
			format_ratio = EXCLUDED.format_ratio, checksum_ratio = EXCLUDED.checksum_ratio,
			rows_inspected = EXCLUDED.rows_inspected, rows_non_null = EXCLUDED.rows_non_null,
			rows_matched = EXCLUDED.rows_matched, unique_estimate = EXCLUDED.unique_estimate,
			sampling_method = EXCLUDED.sampling_method, updated_at = EXCLUDED.updated_at
		RETURNING first_seen_at = updated_at`
	var isNew bool
	err := tx.QueryRow(ctx, upsert, tenantID, item.ColumnID, finding.GetCategoryId(), finding.GetConfidence(),
		evidence.GetNameMatch(), evidence.GetContextMatch(), evidence.GetFormatMatchRatio(), checksum,
		int64(profile.GetRowsInspected()), int64(profile.GetRowsNonNull()), int64(profile.GetRowsMatched()),
		int64(profile.GetUniqueEstimate()), profile.GetSamplingMethod().String(), now).Scan(&isNew)
	if err != nil || !isNew {
		return err
	}
	var tableID uuid.UUID
	if err := tx.QueryRow(ctx, `SELECT table_id FROM asset_columns WHERE id = $1`, item.ColumnID).Scan(&tableID); err != nil {
		return err
	}
	columnID := item.ColumnID
	return recordChange(ctx, tx, tenantID, jobID, asset.ChangeSensitiveAdded, tableID, &columnID, finding.GetCategoryId(), now)
}

// clearStale only touches fully profiled tables: an absent finding in a skipped
// table means it was not looked at, not that the data is gone.
func clearStale(ctx context.Context, tx pgx.Tx, tenantID, jobID uuid.UUID, tables []uuid.UUID, detected map[columnCategory]bool, now time.Time) error {
	const query = `SELECT c.column_id, c.category_id, ac.table_id FROM classifications c
		JOIN asset_columns ac ON ac.id = c.column_id
		WHERE c.status = 'detected' AND ac.table_id = ANY($1)`
	rows, err := tx.Query(ctx, query, tables)
	if err != nil {
		return err
	}
	type stale struct {
		key     columnCategory
		tableID uuid.UUID
	}
	gone, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (stale, error) {
		var item stale
		err := row.Scan(&item.key.columnID, &item.key.category, &item.tableID)
		return item, err
	})
	if err != nil {
		return err
	}
	for _, item := range gone {
		if detected[item.key] {
			continue
		}
		const update = `UPDATE classifications SET status = 'not_detected', updated_at = $3 WHERE column_id = $1 AND category_id = $2`
		if _, err := tx.Exec(ctx, update, item.key.columnID, item.key.category, now); err != nil {
			return err
		}
		columnID := item.key.columnID
		if err := recordChange(ctx, tx, tenantID, jobID, asset.ChangeSensitiveGone, item.tableID, &columnID, item.key.category, now); err != nil {
			return err
		}
	}
	return nil
}
