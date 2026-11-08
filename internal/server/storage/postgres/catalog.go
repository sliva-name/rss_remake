package postgres

import (
	"context"
	"errors"
	"time"

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
		var err error
		entries, err = queryAll(ctx, tx, func(row pgx.Row, entry *asset.CatalogEntry) error {
			return row.Scan(&entry.ColumnID, &entry.TableID, &entry.SourceID, &entry.Database, &entry.Schema,
				&entry.Table, &entry.Column, &entry.NativeType, &entry.CategoryID, &entry.Confidence,
				&entry.NameMatch, &entry.ContextMatch, &entry.FormatRatio, &entry.ChecksumRatio,
				&entry.RowsInspected, &entry.RowsNonNull, &entry.RowsMatched, &entry.UniqueEstimate,
				&entry.SamplingMethod, &entry.UpdatedAt)
		}, columns+catalogFrom+order, sourceID, filter.Category, filter.Limit, filter.Offset)
		return err
	})
	if err != nil {
		return nil, 0, storageError("list catalog", err)
	}
	return entries, total, nil
}

func (s *Store) SummarizeCatalog(ctx context.Context, tenantID uuid.UUID) ([]asset.CategoryCount, error) {
	var counts []asset.CategoryCount
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const query = `SELECT c.category_id, count(*), count(DISTINCT t.id)
			FROM classifications c
			JOIN asset_columns ac ON ac.id = c.column_id AND ac.status = 'active'
			JOIN asset_tables t ON t.id = ac.table_id AND t.status = 'active'
			WHERE c.status = 'detected'
			GROUP BY c.category_id ORDER BY count(*) DESC`
		var err error
		counts, err = queryAll(ctx, tx, func(row pgx.Row, item *asset.CategoryCount) error {
			return row.Scan(&item.Category, &item.Columns, &item.Tables)
		}, query)
		return err
	})
	if err != nil {
		return nil, storageError("summarize catalog", err)
	}
	return counts, nil
}

func (s *Store) ListHistory(ctx context.Context, tenantID uuid.UUID, filter asset.HistoryFilter) ([]asset.HistoryEntry, error) {
	var from, to *time.Time
	if !filter.From.IsZero() {
		from = &filter.From
	}
	if !filter.To.IsZero() {
		to = &filter.To
	}
	var entries []asset.HistoryEntry
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const query = `SELECT h.occurred_at, h.kind, h.table_id, src.source_key, t.table_name, h.column_id,
				COALESCE(ac.column_name, ''), h.category_id
			FROM catalog_changes h
			JOIN asset_tables t ON t.id = h.table_id
			JOIN sources src ON src.id = t.source_id
			LEFT JOIN asset_columns ac ON ac.id = h.column_id
			WHERE ($2::timestamptz IS NULL OR h.occurred_at >= $2) AND ($3::timestamptz IS NULL OR h.occurred_at < $3)
			ORDER BY h.occurred_at DESC LIMIT $1`
		var err error
		entries, err = queryAll(ctx, tx, func(row pgx.Row, entry *asset.HistoryEntry) error {
			return row.Scan(&entry.OccurredAt, &entry.Kind, &entry.TableID, &entry.SourceKey, &entry.TableName, &entry.ColumnID,
				&entry.ColumnName, &entry.CategoryID)
		}, query, filter.Limit, from, to)
		return err
	})
	if err != nil {
		return nil, storageError("list catalog history", err)
	}
	return entries, nil
}

func (s *Store) ListTables(ctx context.Context, tenantID uuid.UUID, filter asset.TableFilter) ([]asset.TableEntry, int64, error) {
	var sourceID *uuid.UUID
	if filter.SourceID != uuid.Nil {
		sourceID = &filter.SourceID
	}
	var entries []asset.TableEntry
	var total int64
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		// The text is matched with strpos, not LIKE, so % and _ in it mean themselves.
		const where = ` WHERE t.status = 'active' AND (@source::uuid IS NULL OR t.source_id = @source)
			AND (@query = '' OR strpos(lower(t.database_name || '.' || t.schema_name || '.' || t.table_name), lower(@query)) > 0)
			AND (NOT @sensitive AND @category = '' OR EXISTS (
				SELECT 1 FROM asset_columns sc JOIN classifications sk ON sk.column_id = sc.id
				WHERE sc.table_id = t.id AND sc.status = 'active' AND sk.status = 'detected' AND (@category = '' OR sk.category_id = @category)))`
		arguments := pgx.NamedArgs{
			"source": sourceID, "query": filter.Query, "sensitive": filter.SensitiveOnly, "category": filter.Category,
			"limit": filter.Limit, "offset": filter.Offset,
		}
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM asset_tables t`+where, arguments).Scan(&total); err != nil {
			return err
		}
		const query = `SELECT t.id, t.source_id, t.database_name, t.schema_name, t.table_name, t.kind, t.last_seen_at,
				count(DISTINCT ac.id),
				count(DISTINCT ac.id) FILTER (WHERE c.status = 'detected'),
				COALESCE(array_agg(DISTINCT c.category_id ORDER BY c.category_id) FILTER (WHERE c.status = 'detected'), '{}')
			FROM asset_tables t
			LEFT JOIN asset_columns ac ON ac.table_id = t.id AND ac.status = 'active'
			LEFT JOIN classifications c ON c.column_id = ac.id` + where + `
			GROUP BY t.id
			ORDER BY t.database_name, t.schema_name, t.table_name LIMIT @limit OFFSET @offset`
		var err error
		entries, err = queryAll(ctx, tx, func(row pgx.Row, entry *asset.TableEntry) error {
			return row.Scan(&entry.ID, &entry.SourceID, &entry.Database, &entry.Schema, &entry.Name, &entry.Kind,
				&entry.LastSeenAt, &entry.Columns, &entry.SensitiveColumns, &entry.Categories)
		}, query, arguments)
		return err
	})
	if err != nil {
		return nil, 0, storageError("list tables", err)
	}
	return entries, total, nil
}

func (s *Store) GetTable(ctx context.Context, tenantID, tableID uuid.UUID) (asset.TableView, error) {
	var view asset.TableView
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const table = `SELECT id, source_id, database_name, schema_name, table_name, kind, status, first_seen_at, last_seen_at
			FROM asset_tables WHERE id = $1`
		if err := tx.QueryRow(ctx, table, tableID).Scan(&view.ID, &view.SourceID, &view.Database, &view.Schema, &view.Name,
			&view.Kind, &view.Status, &view.FirstSeenAt, &view.LastSeenAt); err != nil {
			return err
		}
		const columns = `SELECT ac.id, ac.column_name, ac.native_type, ac.ordinal, ac.nullable,
				COALESCE(array_agg(c.category_id ORDER BY c.category_id) FILTER (WHERE c.status = 'detected'), '{}')
			FROM asset_columns ac
			LEFT JOIN classifications c ON c.column_id = ac.id
			WHERE ac.table_id = $1 AND ac.status = 'active'
			GROUP BY ac.id ORDER BY ac.ordinal`
		var err error
		view.Columns, err = queryAll(ctx, tx, func(row pgx.Row, column *asset.ColumnEntry) error {
			return row.Scan(&column.ID, &column.Name, &column.NativeType, &column.Ordinal, &column.Nullable, &column.Categories)
		}, columns, tableID)
		if err != nil {
			return err
		}
		view.Renames, err = renames(ctx, tx, "table", tableID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return asset.TableView{}, asset.ErrNotFound
	}
	if err != nil {
		return asset.TableView{}, storageError("get table", err)
	}
	return view, nil
}

func (s *Store) GetColumn(ctx context.Context, tenantID, columnID uuid.UUID) (asset.ColumnView, error) {
	var view asset.ColumnView
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const column = `SELECT ac.id, t.id, t.source_id, t.database_name, t.schema_name, t.table_name, ac.column_name,
				ac.native_type, ac.ordinal, ac.nullable, ac.status, ac.first_seen_at, ac.last_seen_at
			FROM asset_columns ac JOIN asset_tables t ON t.id = ac.table_id
			WHERE ac.id = $1`
		if err := tx.QueryRow(ctx, column, columnID).Scan(&view.ID, &view.TableID, &view.SourceID, &view.Database,
			&view.Schema, &view.Table, &view.Name, &view.NativeType, &view.Ordinal, &view.Nullable, &view.Status,
			&view.FirstSeenAt, &view.LastSeenAt); err != nil {
			return err
		}
		const decisions = `SELECT category_id, status = 'detected', confidence, name_match, context_match, format_ratio,
				checksum_ratio, rows_inspected, rows_non_null, rows_matched, unique_estimate, sampling_method,
				first_seen_at, updated_at
			FROM classifications WHERE column_id = $1
			ORDER BY status = 'detected' DESC, confidence DESC, category_id`
		var err error
		view.Classifications, err = queryAll(ctx, tx, func(row pgx.Row, decision *asset.Decision) error {
			return row.Scan(&decision.CategoryID, &decision.Detected, &decision.Confidence, &decision.NameMatch,
				&decision.ContextMatch, &decision.FormatRatio, &decision.ChecksumRatio, &decision.RowsInspected,
				&decision.RowsNonNull, &decision.RowsMatched, &decision.UniqueEstimate, &decision.SamplingMethod,
				&decision.FirstSeenAt, &decision.UpdatedAt)
		}, decisions, columnID)
		if err != nil {
			return err
		}
		view.Renames, err = renames(ctx, tx, "column", columnID)
		return err
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return asset.ColumnView{}, asset.ErrNotFound
	}
	if err != nil {
		return asset.ColumnView{}, storageError("get column", err)
	}
	return view, nil
}

func renames(ctx context.Context, tx pgx.Tx, kind string, objectID uuid.UUID) ([]asset.RenameRecord, error) {
	return queryAll(ctx, tx, func(row pgx.Row, record *asset.RenameRecord) error {
		return row.Scan(&record.OldName, &record.NewName, &record.DetectedAt, &record.DetectedBy)
	}, `SELECT old_name, new_name, detected_at, detected_by FROM asset_renames
		WHERE object_kind = $1 AND object_id = $2 ORDER BY detected_at`, kind, objectID)
}

// Search finds active tables and columns by part of their name. Exact and
// prefix matches come first, then the shorter names.
func (s *Store) Search(ctx context.Context, tenantID uuid.UUID, text string, limit int) (asset.Matches, error) {
	var matches asset.Matches
	err := s.inTenant(ctx, tenantID, func(tx pgx.Tx) error {
		const tables = `SELECT id, source_id, database_name, schema_name, table_name FROM asset_tables
			WHERE status = 'active' AND strpos(lower(table_name), lower($1)) > 0
			ORDER BY strpos(lower(table_name), lower($1)), length(table_name), table_name LIMIT $2`
		var err error
		matches.Tables, err = queryAll(ctx, tx, func(row pgx.Row, match *asset.TableMatch) error {
			return row.Scan(&match.ID, &match.SourceID, &match.Database, &match.Schema, &match.Name)
		}, tables, text, limit)
		if err != nil {
			return err
		}
		const columns = `SELECT ac.id, t.source_id, t.schema_name, t.table_name, ac.column_name,
				COALESCE(array_agg(c.category_id ORDER BY c.category_id) FILTER (WHERE c.status = 'detected'), '{}')
			FROM asset_columns ac
			JOIN asset_tables t ON t.id = ac.table_id AND t.status = 'active'
			LEFT JOIN classifications c ON c.column_id = ac.id
			WHERE ac.status = 'active' AND strpos(lower(ac.column_name), lower($1)) > 0
			GROUP BY ac.id, t.id
			ORDER BY strpos(lower(ac.column_name), lower($1)), length(ac.column_name), ac.column_name, t.table_name LIMIT $2`
		matches.Columns, err = queryAll(ctx, tx, func(row pgx.Row, match *asset.ColumnMatch) error {
			return row.Scan(&match.ID, &match.SourceID, &match.Schema, &match.Table, &match.Name, &match.Categories)
		}, columns, text, limit)
		return err
	})
	if err != nil {
		return asset.Matches{}, storageError("search catalog", err)
	}
	return matches, nil
}
