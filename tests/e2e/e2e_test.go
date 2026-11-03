//go:build e2e

// Package e2e drives the platform's containers on the real stand: Keycloak issues
// the tokens, the server and the agent run from their images, and a browser in
// its own container walks the dashboard.
package e2e_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"dataguard/internal/agent/queue"
	"dataguard/internal/gen/restapi"
	"dataguard/internal/platform/sealing"
	"dataguard/internal/testkit/keycloak"
	"dataguard/internal/testkit/seed"
	"dataguard/internal/testkit/stand"
	"dataguard/internal/testkit/synthetic"
	"dataguard/sdk/go/appcontext"
)

const (
	api         = "http://127.0.0.1:25800"
	wait        = 60 * time.Second
	seededRows  = 200
	agentConfig = "/etc/dataguard/agent.yaml"
	agentVolume = "dataguard-dev_agent-state"
)

func root(t *testing.T) string {
	t.Helper()
	directory, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

// compose runs docker compose on the stand and returns its standard output.
func compose(t *testing.T, stdin io.Reader, env []string, arguments ...string) string {
	t.Helper()
	output, err := composeOutput(root(t), stdin, env, arguments...)
	if err != nil {
		t.Fatalf("docker compose %s: %v", strings.Join(arguments, " "), err)
	}
	return output
}

func composeOutput(directory string, stdin io.Reader, env []string, arguments ...string) (string, error) {
	base := []string{
		"compose", "--project-name", "dataguard-dev", "--env-file", "deployments/dev/.env",
		"-f", "deployments/dev/compose.yml", "--profile", "agent", "--profile", "check",
	}
	command := exec.Command("docker", append(base, arguments...)...)
	command.Dir = directory
	command.Stdin = stdin
	command.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("%w\n%s%s", err, stdout.String(), stderr.String())
	}
	return stdout.String(), nil
}

type stack struct {
	token    string
	tenantID string
	password string
	sources  []stand.Source
	appKey   ed25519.PrivateKey
}

// bringUp builds the images and starts the center. The agent gets a new identity
// and an empty queue on every run.
func bringUp(t *testing.T) *stack {
	t.Helper()
	compose(t, nil, nil, "build", "pki-init", "agent", "browser-check")
	compose(t, nil, nil, "rm", "--stop", "--force", "agent")
	if output, err := exec.Command("docker", "volume", "rm", "--force", agentVolume).CombinedOutput(); err != nil {
		t.Fatalf("remove agent state: %v\n%s", err, output)
	}
	compose(t, nil, nil, "up", "--detach", "--wait", "server",
		"source-postgres", "source-mysql", "source-mariadb", "source-mssql")
	directory := root(t)
	t.Cleanup(func() { _, _ = composeOutput(directory, nil, nil, "stop", "agent") })
	waitReady(t)
	return &stack{}
}

func waitReady(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		response, err := http.Get(api + "/readyz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("server did not become ready:\n%s", logs(t, "server"))
}

func logs(t *testing.T, service string) string {
	t.Helper()
	return compose(t, nil, nil, "logs", "--no-color", "--no-log-prefix", service)
}

func kill(t *testing.T, service string) {
	t.Helper()
	compose(t, nil, nil, "kill", "--signal", "SIGKILL", service)
}

// startAgent keeps the existing container, so its log covers every restart.
func startAgent(t *testing.T) {
	t.Helper()
	compose(t, nil, nil, "up", "--detach", "--no-deps", "agent")
}

func startServer(t *testing.T) {
	t.Helper()
	compose(t, nil, nil, "start", "server")
	waitReady(t)
}

// createUser replaces any user left by a previous run.
func createUser(t *testing.T, name, role, tenantID string) string {
	t.Helper()
	ctx := context.Background()
	admin, err := keycloak.Connect(ctx, stand.Env(t)["KEYCLOAK_ADMIN_PASSWORD"])
	if err != nil {
		t.Fatal(err)
	}
	password, err := admin.CreateUser(ctx, name, role, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	return password
}

func hexToken(t *testing.T) string {
	t.Helper()
	buffer := make([]byte, 12)
	if _, err := rand.Read(buffer); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", buffer)
}

func login(t *testing.T, name, password string) string {
	t.Helper()
	token, err := keycloak.Login(context.Background(), name, password)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func (s *stack) call(t *testing.T, token, method, path string, body any, into any) int {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, api+"/api/v1"+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if into != nil && response.StatusCode < 300 {
		if err := json.NewDecoder(response.Body).Decode(into); err != nil {
			t.Fatal(err)
		}
	}
	return response.StatusCode
}

func (s *stack) must(t *testing.T, method, path string, body, into any) {
	t.Helper()
	if status := s.call(t, s.token, method, path, body, into); status >= 300 {
		t.Fatalf("%s %s: %d", method, path, status)
	}
}

// onboard walks the path of a real customer: a platform administrator creates the
// organization, its administrator issues a token, the agent enrolls with it.
func (s *stack) onboard(t *testing.T) {
	t.Helper()
	suffix := hexToken(t)[:6]
	platformPassword := createUser(t, "dg-platform", "platform_admin", "")
	platformToken := login(t, "dg-platform", platformPassword)
	var tenant restapi.Tenant
	if status := s.call(t, platformToken, http.MethodPost, "/tenants", restapi.NewTenant{Name: "Acme " + suffix}, &tenant); status != http.StatusCreated {
		t.Fatalf("create tenant: %d", status)
	}
	s.tenantID = tenant.Id.String()
	s.password = createUser(t, "dg-admin", "tenant_admin", s.tenantID)
	s.token = login(t, "dg-admin", s.password)
	var environment restapi.Environment
	s.must(t, http.MethodPost, "/environments", restapi.NewEnvironment{Name: "production", Kind: restapi.Production}, &environment)
	var token restapi.EnrollmentToken
	s.must(t, http.MethodPost, "/enrollment-tokens", restapi.NewEnrollmentToken{EnvironmentId: environment.Id}, &token)
	s.sources = stand.AllSources(t)
	s.appKey = applicationKey(t)
	compose(t, strings.NewReader(token.Token), nil,
		"run", "--rm", "--no-deps", "-T", "agent", "enroll", "--config", agentConfig, "--token-file", "/dev/stdin")
	startAgent(t)
	s.defineSources(t)
}

// containerSource is a stand database as the agent container reaches it.
type containerSource struct {
	name, engine, host, auditDirectory, passwordKey, tls string
	port                                                 int
}

var containerSources = []containerSource{
	{"crm-postgres", "postgresql", "source-postgres", "/var/log/dg-audit/postgres", "SOURCE_SCANNER_PASSWORD", "disable", 5432},
	{"crm-mysql", "mysql", "source-mysql", "/var/log/dg-audit/mysql", "SOURCE_SCANNER_PASSWORD", "disable", 3306},
	{"crm-mariadb", "mariadb", "source-mariadb", "/var/log/dg-audit/mariadb", "SOURCE_SCANNER_PASSWORD", "disable", 3306},
	{"crm-mssql", "mssql", "source-mssql", "/var/opt/mssql/dg-audit", "SOURCE_MSSQL_SCANNER_PASSWORD", "require", 1433},
}

// defineSources does what an administrator does in the dashboard: the password
// is sealed to the agent's published key before it is sent to the center.
func (s *stack) defineSources(t *testing.T) {
	t.Helper()
	var agents []restapi.Agent
	s.must(t, http.MethodGet, "/agents", nil, &agents)
	if len(agents) != 1 || agents[0].SealingPublicKey == nil {
		t.Fatalf("the agent published no sealing key: %+v", agents)
	}
	env := stand.Env(t)
	for _, item := range containerSources {
		sealed, err := sealing.Seal(*agents[0].SealingPublicKey, sealing.Binding{
			TenantID: uuid.MustParse(s.tenantID), AgentID: agents[0].Id, Engine: item.engine, Host: item.host,
			Port: item.port, Database: "crm", Username: "dg_scanner", TLS: item.tls,
		}, []byte(env[item.passwordKey]))
		if err != nil {
			t.Fatal(err)
		}
		directory := item.auditDirectory
		s.must(t, http.MethodPost, "/sources", restapi.NewSource{
			Name: item.name, AgentId: agents[0].Id, Engine: restapi.SourceEngine(item.engine), Host: item.host,
			Port: item.port, Database: "crm", Username: "dg_scanner", Tls: restapi.TlsMode(item.tls),
			AuditDirectory: &directory, SealedPassword: sealed,
		}, nil)
	}
}

// applicationKey is the stand's signing key of the application "crm"; the agent
// container has its public half.
func applicationKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join(root(t), "deployments", "dev", ".state", "apps", "crm.seed"))
	if err != nil {
		t.Fatalf("application key is missing, run make dev-up: %v", err)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatal("crm.seed is not a base64 ed25519 seed")
	}
	return ed25519.NewKeyFromSeed(seed)
}

func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out: %s", what)
}

func (s *stack) coverage(t *testing.T) []restapi.CoverageRow {
	t.Helper()
	var rows []restapi.CoverageRow
	s.must(t, http.MethodGet, "/audit/coverage", nil, &rows)
	return rows
}

func (s *stack) eventTotal(t *testing.T, query string) int64 {
	t.Helper()
	var page restapi.AuditEventPage
	s.must(t, http.MethodGet, "/audit/events?limit=1"+query, nil, &page)
	return page.Total
}

// sensitiveValues reads what is really in the source, so the leak search uses the
// values themselves and not only a marker planted in some of them.
func sensitiveValues(t *testing.T, source *stand.Source) []string {
	t.Helper()
	rows, err := source.Admin.Query(`SELECT email, phone, inn, snils, card_number, passport FROM ` + seed.Users)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var values []string
	for rows.Next() {
		row := make([]sql.NullString, 6)
		if err := rows.Scan(&row[0], &row[1], &row[2], &row[3], &row[4], &row[5]); err != nil {
			t.Fatal(err)
		}
		for _, value := range row {
			values = append(values, value.String)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(values) == 0 {
		t.Fatal("no values to search for")
	}
	return values
}

// dumpPostgres reads the center database as its owner, past row-level security.
func dumpPostgres(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	dsn := url.URL{
		Scheme: "postgres", User: url.UserPassword("dg_owner", stand.Env(t)["CENTER_PG_ADMIN_PASSWORD"]),
		Host: "127.0.0.1:25442", Path: "/dataguard", RawQuery: "sslmode=disable",
	}
	connection, err := pgx.Connect(ctx, dsn.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close(ctx) }()
	rows, err := connection.Query(ctx, `SELECT tablename FROM pg_tables WHERE schemaname = 'public'`)
	if err != nil {
		t.Fatal(err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	var dump strings.Builder
	for _, table := range tables {
		lines, err := connection.Query(ctx, fmt.Sprintf(`SELECT t::text FROM %s t`, pgx.Identifier{table}.Sanitize()))
		if err != nil {
			t.Fatal(err)
		}
		values, err := pgx.CollectRows(lines, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		dump.WriteString(strings.Join(values, "\n"))
	}
	return dump.String()
}

func dumpClickHouse(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	admin := stand.Env(t)["CENTER_CH_ADMIN_PASSWORD"]
	connection, err := chdriver.Open(&chdriver.Options{
		Addr: []string{"127.0.0.1:25900"},
		Auth: chdriver.Auth{Database: "dataguard", Username: "dg_ch_admin", Password: admin},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	rows, err := connection.Query(ctx, `SELECT toString(tuple(*)) FROM audit_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var dump strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		dump.WriteString(line + "\n")
	}
	return dump.String()
}

func assertAbsent(t *testing.T, where, haystack string, values []string) {
	t.Helper()
	if haystack == "" {
		t.Fatalf("%s is empty, the search proves nothing", where)
	}
	for _, value := range values {
		if value != "" && strings.Contains(haystack, value) {
			t.Fatalf("%s contains a source value", where)
		}
	}
}

func TestPlatformEndToEnd(t *testing.T) {
	ctx := context.Background()
	s := bringUp(t)
	s.onboard(t)

	var all []string
	for i := range s.sources {
		source := &s.sources[i]
		if err := seed.Tables(ctx, source.Admin, source.Dialect, seededRows, synthetic.New(uint64(i+100))); err != nil {
			t.Fatalf("seed %s: %v", source.Dialect.Name, err)
		}
		source.Admin.SetMaxIdleConns(0)
		all = append(all, sensitiveValues(t, source)...)
	}

	t.Run("agent reports every source honestly", func(t *testing.T) {
		eventually(t, "all sources observed", func() bool {
			rows := s.coverage(t)
			observing := 0
			for _, row := range rows {
				if row.Status == restapi.OBSERVING {
					observing++
				}
			}
			return len(rows) == len(s.sources) && observing == len(s.sources)
		})
		var sources []restapi.Source
		s.must(t, http.MethodGet, "/sources", nil, &sources)
		for _, source := range sources {
			if source.EngineVersion == "" {
				t.Errorf("%s has no version", source.Key)
			}
			for _, capability := range source.Capabilities {
				if capability.Capability == "CAPABILITY_RETURNED_ROWS" && capability.Support == "SUPPORT_AVAILABLE" {
					t.Errorf("%s claims returned rows", source.Key)
				}
			}
		}
	})

	t.Run("scans classify every engine", func(t *testing.T) {
		var sources []restapi.Source
		s.must(t, http.MethodGet, "/sources", nil, &sources)
		for _, source := range sources {
			s.must(t, http.MethodPost, "/scans", restapi.NewScan{SourceId: source.Id}, nil)
		}
		eventually(t, "scans finished", func() bool {
			var scans []restapi.Scan
			s.must(t, http.MethodGet, "/scans", nil, &scans)
			for _, scan := range scans {
				if scan.Status != restapi.Completed {
					return false
				}
			}
			return len(scans) == len(sources)
		})
		var page restapi.CatalogPage
		s.must(t, http.MethodGet, "/catalog/columns?category=GOVERNMENT.TAX_ID", nil, &page)
		if page.Total != int64(len(sources)) {
			t.Fatalf("tax id columns = %d", page.Total)
		}
		var inventory []restapi.CategoryInventory
		s.must(t, http.MethodGet, "/catalog/summary", nil, &inventory)
		if len(inventory) < 6 {
			t.Fatalf("inventory = %+v", inventory)
		}
	})

	t.Run("traffic is attributed", func(t *testing.T) {
		postgres := &s.sources[0]
		for i := range s.sources {
			source := &s.sources[i]
			query := fmt.Sprintf(`SELECT email, inn FROM %s WHERE email = '%s.e2e@example.invalid'`, seed.Users, synthetic.CanaryMarker)
			if _, err := source.Admin.ExecContext(ctx, query); err != nil {
				t.Fatalf("%s: %v", source.Dialect.Name, err)
			}
		}
		token, err := appcontext.NewSigner("crm", s.appKey).Token("employee-123", "dg_app", "")
		if err != nil {
			t.Fatal(err)
		}
		tx, err := postgres.Admin.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := appcontext.Apply(ctx, tx, token); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `SELECT phone FROM `+seed.Users); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		eventually(t, "verified user appears", func() bool {
			var principals []restapi.PrincipalAccess
			s.must(t, http.MethodGet, "/analytics/principals", nil, &principals)
			for _, item := range principals {
				if item.ApplicationPrincipal == "employee-123" && item.IdentityConfidence == "IDENTITY_CONFIDENCE_VERIFIED" {
					return true
				}
			}
			return false
		})
		eventually(t, "access to tax ids from all engines", func() bool {
			return s.eventTotal(t, "&category=GOVERNMENT.TAX_ID&principal=dg_app") >= int64(len(s.sources))
		})
	})

	t.Run("agent killed with SIGKILL loses nothing", func(t *testing.T) {
		source := &s.sources[0]
		before := s.eventTotal(t, "&principal=dg_app&category=PERSONAL.EMAIL")
		kill(t, "agent")
		const statements = 20
		for i := range statements {
			if _, err := source.Admin.ExecContext(ctx, fmt.Sprintf(`SELECT email, %d FROM %s`, i, seed.Users)); err != nil {
				t.Fatal(err)
			}
		}
		startAgent(t)
		eventually(t, "events from the outage", func() bool {
			return s.eventTotal(t, "&principal=dg_app&category=PERSONAL.EMAIL")-before >= statements
		})
	})

	t.Run("server restart loses nothing", func(t *testing.T) {
		source := &s.sources[1]
		before := s.eventTotal(t, "&principal=dg_app&category=PERSONAL.PHONE")
		kill(t, "server")
		const statements = 15
		for i := range statements {
			if _, err := source.Admin.ExecContext(ctx, fmt.Sprintf(`SELECT phone, %d FROM %s`, i, seed.Users)); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(3 * time.Second)
		startServer(t)
		eventually(t, "events delivered after restart", func() bool {
			return s.eventTotal(t, "&principal=dg_app&category=PERSONAL.PHONE")-before >= statements
		})
	})

	t.Run("no source value left the source", func(t *testing.T) {
		// The scanner passwords must not reach the center either: it holds them sealed.
		env := stand.Env(t)
		values := append(slices.Clone(all), synthetic.CanaryMarker, env["SOURCE_SCANNER_PASSWORD"], env["SOURCE_MSSQL_SCANNER_PASSWORD"])
		assertAbsent(t, "agent log", logs(t, "agent"), values)
		assertAbsent(t, "server log", logs(t, "server"), values)
		assertAbsent(t, "central postgres", dumpPostgres(t), values)
		assertAbsent(t, "clickhouse", dumpClickHouse(t), values)
		s.assertQueueClean(t, values)
	})

	t.Run("dashboard works in a browser", func(t *testing.T) {
		// Screenshots land in deployments/dev/.state/browser.
		// The browser also adds a source through the form, sealing its password itself.
		compose(t, nil, []string{
			"DG_UI_USER=dg-admin", "DG_UI_PASSWORD=" + s.password, "DG_UI_SOURCE_PASSWORD=" + stand.Env(t)["SOURCE_SCANNER_PASSWORD"],
		}, "run", "--rm", "-e", "DG_UI_USER", "-e", "DG_UI_PASSWORD", "-e", "DG_UI_SOURCE_PASSWORD", "browser-check")
	})

	t.Run("revoked agent stops immediately", func(t *testing.T) {
		var agents []restapi.Agent
		s.must(t, http.MethodGet, "/agents", nil, &agents)
		s.must(t, http.MethodPost, "/agents/"+agents[0].Id.String()+"/revoke", nil, nil)
		var refreshed []restapi.Agent
		eventually(t, "heartbeats stop", func() bool {
			s.must(t, http.MethodGet, "/agents", nil, &refreshed)
			return refreshed[0].Status == restapi.Revoked
		})
		first := refreshed[0].LastSeenAt
		time.Sleep(35 * time.Second)
		s.must(t, http.MethodGet, "/agents", nil, &refreshed)
		if !refreshed[0].LastSeenAt.Equal(*first) {
			t.Fatal("a revoked agent is still reporting")
		}
	})
}

// assertQueueClean copies the stopped agent's state out of its container and
// opens the queue. The agent must be stopped, because the file is locked while it runs.
func (s *stack) assertQueueClean(t *testing.T, values []string) {
	t.Helper()
	kill(t, "agent")
	container := strings.TrimSpace(compose(t, nil, nil, "ps", "--all", "--quiet", "agent"))
	if container == "" {
		t.Fatal("agent container not found")
	}
	state := filepath.Join(t.TempDir(), "state")
	if output, err := exec.Command("docker", "cp", container+":/var/lib/dataguard", state).CombinedOutput(); err != nil {
		t.Fatalf("copy agent state: %v\n%s", err, output)
	}
	stored, err := queue.Open(state, 1<<24)
	if err != nil {
		t.Fatal(err)
	}
	items, err := stored.Peek(100_000, 1<<30)
	if err != nil {
		t.Fatal(err)
	}
	var dump strings.Builder
	dump.WriteString("queue")
	for _, item := range items {
		dump.WriteString(item.Event.String())
	}
	if err := stored.Close(); err != nil {
		t.Fatal(err)
	}
	assertAbsent(t, "agent queue", dump.String(), values)
	startAgent(t)
}
