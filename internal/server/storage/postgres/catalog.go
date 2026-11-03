package postgres

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"dataguard/internal/core/asset"
)

const catalogFrom = `FROM classifications c
	JOIN asset_columns ac ON ac.id = c.column_id AND ac.status = 'active'
	JOIN asset_tables t ON t.id = ac.table_id AND t.status = 'active'
	WHERE c.status = 'detected'
	  AND ($1::uuid IS NULL OR t.source_id = $1)
	  AND ($2 = '' OR c.category_id = $2)`

func (s *Store) ListCatalog(ctx context.Context, tenantID uuid.UUID, filter asset.CatalogFilter) ([]asset.CatalogEntry, int64, error) {
	var sourceID *uuid.UUID
	if filter.SourceID != uuid.Nil {
		sourceID = &filter.SourceID
	}
	var entries []asset.CatalogEntry
	var total int64
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) `+catalogFrom, sourceID, filter.Category).Scan(&total); err != nil {
			return err
		}
		const columns = `SELECT ac.id, t.id, t.source_id, t.database_name, t.schema_name, t.table_name,
			ac.column_name, ac.native_type, c.category_id, c.confidence, c.name_match, c.context_match,
			c.format_ratio, c.checksum_ratio, c.rows_inspected, c.rows_non_null, c.rows_matched,
			c.unique_estimate, c.sampling_method, c.updated_at `
		const order = ` ORDER BY t.schema_name, t.table_name, ac.ordinal, c.category_id LIMIT $3 OFFSET $4`
		rows, err := tx.Query(ctx, columns+catalogFrom+order, sourceID, filter.Category, filter.Limit, filter.Offset)
		if err != nil {
			return err
		}
		entries, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (asset.CatalogEntry, error) {
			var entry asset.CatalogEntry
			err := row.Scan(&entry.ColumnID, &entry.TableID, &entry.SourceID, &entry.Database, &entry.Schema,
				&entry.Table, &entry.Column, &entry.NativeType, &entry.CategoryID, &entry.Confidence,
				&entry.NameMatch, &entry.ContextMatch, &entry.FormatRatio, &entry.ChecksumRatio,
				&entry.RowsInspected, &entry.RowsNonNull, &entry.RowsMatched, &entry.UniqueEstimate,
				&entry.SamplingMethod, &entry.UpdatedAt)
			return entry, err
		})
		return err
	})
	if err != nil {
		return nil, 0, storageError("list catalog", err)
	}
	return entries, total, nil
}

func (s *Store) ListHistory(ctx context.Context, tenantID uuid.UUID, limit int) ([]asset.HistoryEntry, error) {
	var entries []asset.HistoryEntry
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const query = `SELECT h.occurred_at, h.kind, h.table_id, t.table_name, h.column_id,
				COALESCE(ac.column_name, ''), h.category_id
			FROM catalog_changes h
			JOIN asset_tables t ON t.id = h.table_id
			LEFT JOIN asset_columns ac ON ac.id = h.column_id
			ORDER BY h.occurred_at DESC LIMIT $1`
		rows, err := tx.Query(ctx, query, limit)
		if err != nil {
			return err
		}
		entries, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (asset.HistoryEntry, error) {
			var entry asset.HistoryEntry
			err := row.Scan(&entry.OccurredAt, &entry.Kind, &entry.TableID, &entry.TableName, &entry.ColumnID,
				&entry.ColumnName, &entry.CategoryID)
			return entry, err
		})
		return err
	})
	if err != nil {
		return nil, storageError("list catalog history", err)
	}
	return entries, nil
}
