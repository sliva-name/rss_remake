//go:build integration

package integration_test

import (
	"os"
	"testing"

	"dataguard/internal/query/frontend/postgres"
)

// TestMain compiles the PostgreSQL parser before any test starts. Its WebAssembly
// module is compiled on the first parse: under a second without the race
// detector, several seconds with it on a busy runner, which would otherwise be
// spent inside the first audit test's wait.
func TestMain(m *testing.M) {
	_, _ = postgres.Frontend{}.Parse("SELECT 1")
	os.Exit(m.Run())
}
