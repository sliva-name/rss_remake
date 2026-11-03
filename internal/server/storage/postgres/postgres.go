// Package postgres implements the core repositories. All tenant data is
// reached through inTenant, which sets the row-security context, so a forgotten
// WHERE clause returns nothing instead of another tenant's rows.
package postgres

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib" // registers the driver used by goose
	"github.com/pressly/goose/v3"

	"dataguard/internal/platform/safeerr"
)

const uniqueViolation = "23505"

// Store is the runtime connection pool. It must connect as a role without
// BYPASSRLS; RequireRowSecurity verifies that at startup.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects and refuses a role that would silently bypass row security.
func Open(ctx context.Context, dsn string) (*Store, error) {
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, safeerr.New("open postgres", safeerr.CodeInvalid, err)
	}
	store := &Store{pool: pool}
	if err := store.requireRowSecurity(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return store, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Ping reports whether the database answers.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return safeerr.New("ping postgres", safeerr.CodeUnavailable, err)
	}
	return nil
}

func (s *Store) requireRowSecurity(ctx context.Context) error {
	const query = `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`
	var bypasses bool
	if err := s.pool.QueryRow(ctx, query).Scan(&bypasses); err != nil {
		return storageError("check runtime role", err)
	}
	if bypasses {
		return &safeerr.Error{Op: "runtime role bypasses row security", Code: safeerr.CodeInvalid}
	}
	return nil
}

func (s *Store) inTenant(ctx context.Context, tenantID uuid.UUID, work func(pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		const setTenant = `SELECT set_config('app.tenant_id', $1, true)`
		if _, err := tx.Exec(ctx, setTenant, tenantID.String()); err != nil {
			return err
		}
		return work(tx)
	})
}

// storageError keeps the SQLSTATE, which is value-free, and drops the message,
// which can quote row data.
func storageError(op string, err error) error {
	if pgError, ok := errors.AsType[*pgconn.PgError](err); ok {
		op += " (" + pgError.Code + ")"
	}
	return safeerr.New(op, safeerr.CodeInternal, err)
}

func isUniqueViolation(err error) bool {
	pgError, ok := errors.AsType[*pgconn.PgError](err)
	return ok && pgError.Code == uniqueViolation
}

// Migrate applies embedded migrations. It runs as the schema owner, separately
// from the runtime role.
func Migrate(ctx context.Context, dsn string, migrations embed.FS, directory string) error {
	database, err := sql.Open("pgx", dsn)
	if err != nil {
		return fmt.Errorf("open migration connection: %w", err)
	}
	defer func() { _ = database.Close() }()

	provider, err := goose.NewProvider(goose.DialectPostgres, database, subFS(migrations, directory))
	if err != nil {
		return fmt.Errorf("prepare migrations: %w", err)
	}
	if _, err := provider.Up(ctx); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}
