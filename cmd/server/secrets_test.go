package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeSecret(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestSecretComesFromFileOrVariable(t *testing.T) {
	t.Setenv("DG_TEST_SECRET_FILE", writeSecret(t, "from-file\n"))
	if value, err := secret("DG_TEST_SECRET"); err != nil || value != "from-file" {
		t.Fatalf("file: %q, %v", value, err)
	}
	t.Setenv("DG_TEST_SECRET_FILE", "")
	t.Setenv("DG_TEST_SECRET", "direct")
	if value, err := secret("DG_TEST_SECRET"); err != nil || value != "direct" {
		t.Fatalf("variable: %q, %v", value, err)
	}
}

func TestSecretRefusesAmbiguityAndEmptyFiles(t *testing.T) {
	t.Setenv("DG_TEST_SECRET", "direct")
	t.Setenv("DG_TEST_SECRET_FILE", writeSecret(t, "from-file"))
	if _, err := secret("DG_TEST_SECRET"); err == nil {
		t.Fatal("both ways at once were accepted")
	}
	t.Setenv("DG_TEST_SECRET", "")
	t.Setenv("DG_TEST_SECRET_FILE", writeSecret(t, "\n"))
	if _, err := secret("DG_TEST_SECRET"); err == nil {
		t.Fatal("an empty file was accepted")
	}
	t.Setenv("DG_TEST_SECRET_FILE", filepath.Join(t.TempDir(), "missing"))
	if _, err := secret("DG_TEST_SECRET"); err == nil {
		t.Fatal("a missing file was accepted")
	}
}

func TestPasswordGoesIntoTheConnectionString(t *testing.T) {
	t.Setenv("DG_TEST_DSN", "postgres://dg_runtime@db:5432/dataguard?sslmode=verify-full")
	t.Setenv("DG_TEST_PASSWORD_FILE", writeSecret(t, "p@ss/word:?#\n"))
	dsn, err := postgresDSN("DG_TEST_DSN", "DG_TEST_PASSWORD")
	if err != nil {
		t.Fatal(err)
	}
	if want := "postgres://dg_runtime:p%40ss%2Fword%3A%3F%23@db:5432/dataguard?sslmode=verify-full"; dsn != want {
		t.Fatalf("dsn = %q, want %q", dsn, want)
	}
}

func TestPasswordIsNotSetTwice(t *testing.T) {
	t.Setenv("DG_TEST_PASSWORD", "secret")
	for _, dsn := range []string{
		"postgres://dg_runtime:other@db/dataguard",
		"postgres://db/dataguard",
		"host=db user=dg_runtime",
	} {
		t.Setenv("DG_TEST_DSN", dsn)
		if _, err := postgresDSN("DG_TEST_DSN", "DG_TEST_PASSWORD"); err == nil {
			t.Errorf("%q was accepted", dsn)
		}
	}
	t.Setenv("DG_TEST_PASSWORD", "")
	t.Setenv("DG_TEST_DSN", "postgres://dg_runtime:inline@db/dataguard")
	if dsn, err := postgresDSN("DG_TEST_DSN", "DG_TEST_PASSWORD"); err != nil || dsn != "postgres://dg_runtime:inline@db/dataguard" {
		t.Fatalf("without a separate password the string is kept: %q, %v", dsn, err)
	}
}
