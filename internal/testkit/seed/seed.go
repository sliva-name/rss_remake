// Package seed fills the stand's source databases with synthetic data.
package seed

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"dataguard/internal/testkit/synthetic"
)

// Dialect differences that matter to the seed.
type Dialect struct {
	Name         string
	Text         string
	Bigint       string
	Quote        func(string) string
	Placeholders func(count int) string
}

// Users is a table a scanner must classify column by column.
const Users = "dg_users"

// Orders holds digit strings that must not be classified.
const Orders = "dg_orders"

// Tables creates and fills the test tables, replacing any previous run.
func Tables(ctx context.Context, db *sql.DB, dialect Dialect, rows int, generator *synthetic.Generator) error {
	if err := recreate(ctx, db, dialect, Users, []string{
		"id " + dialect.Bigint, "email " + dialect.Text, "phone " + dialect.Text, "inn " + dialect.Text,
		"snils " + dialect.Text, "card_number " + dialect.Text, "passport " + dialect.Text,
		"first_name " + dialect.Text, "status " + dialect.Text,
	}); err != nil {
		return err
	}
	if err := recreate(ctx, db, dialect, Orders, []string{
		"id " + dialect.Bigint, "external_ref " + dialect.Text, "note " + dialect.Text,
	}); err != nil {
		return err
	}
	for i := range rows {
		if err := insert(ctx, db, dialect, Users, []any{
			int64(i + 1), generator.Email(), generator.PhoneRU(), generator.INN12(), generator.SNILS(),
			generator.PaymentCard(), generator.PassportRU(), synthetic.CanaryMarker + "name", "active",
		}); err != nil {
			return err
		}
		if err := insert(ctx, db, dialect, Orders, []any{
			int64(i + 1), generator.RandomDigits(12), "delivered",
		}); err != nil {
			return err
		}
	}
	return nil
}

func recreate(ctx context.Context, db *sql.DB, dialect Dialect, table string, columns []string) error {
	if _, err := db.ExecContext(ctx, "DROP TABLE IF EXISTS "+dialect.Quote(table)); err != nil {
		return fmt.Errorf("drop %s: %w", table, err)
	}
	statement := fmt.Sprintf("CREATE TABLE %s (%s)", dialect.Quote(table), strings.Join(columns, ", "))
	if _, err := db.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("create %s: %w", table, err)
	}
	return nil
}

func insert(ctx context.Context, db *sql.DB, dialect Dialect, table string, values []any) error {
	//nolint:gosec // Table names are constants of this package; values are bound.
	statement := fmt.Sprintf("INSERT INTO %s VALUES (%s)", dialect.Quote(table), dialect.Placeholders(len(values)))
	if _, err := db.ExecContext(ctx, statement, values...); err != nil {
		return fmt.Errorf("insert into %s: %w", table, err)
	}
	return nil
}
