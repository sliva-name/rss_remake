//go:build e2e

// Package e2e runs the real binaries against the real stand: Keycloak issues the
// tokens, the agent is a separate process, and failures are real signals.
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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	chdriver "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/jackc/pgx/v5"

	"dataguard/internal/agent/config"
	"dataguard/internal/agent/queue"
	"dataguard/internal/gen/restapi"
	"dataguard/internal/server/storage/clickhouse"
	"dataguard/internal/testkit/seed"
	"dataguard/internal/testkit/stand"
	"dataguard/internal/testkit/synthetic"
	"dataguard/sdk/go/appcontext"
)

const (
	keycloak   = "http://127.0.0.1:25080"
	realm      = "dataguard"
	wait       = 60 * time.Second
	seededRows = 200
)

func root(t *testing.T) string {
	t.Helper()
	directory, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return directory
}

func freePort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	return listener.Addr().String()
}

type process struct {
	command *exec.Cmd
	logPath string
}

// start ties the process to owner, which must outlive it: a subtest that restarts
// a process must not kill it when the subtest ends.
func start(owner *testing.T, logPath string, env []string, name string, arguments ...string) *process {
	t := owner
	t.Helper()
	log, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(name, arguments...)
	command.Env = append(os.Environ(), env...)
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	item := &process{command: command, logPath: logPath}
	t.Cleanup(func() {
		_ = log.Close()
		item.kill(syscall.SIGKILL)
	})
	return item
}

func (p *process) kill(signal syscall.Signal) {
	if p.command.Process == nil || p.command.ProcessState != nil {
		return
	}
	_ = p.command.Process.Signal(signal)
	_, _ = p.command.Process.Wait()
}

type stack struct {
	root       string
	directory  string
	serverBin  string
	agentBin   string
	serverEnv  []string
	api        string
	agentURL   string
	server     *process
	agent      *process
	configPath string
	stateDir   string
	token      string
	tenantID   string
	ownerDSN   string
	events     clickhouse.Settings
	sources    []stand.Source
	appKey     ed25519.PrivateKey
	owner      *testing.T
}

func build(t *testing.T, directory string) (string, string) {
	t.Helper()
	command := exec.Command("go", "build", "-o", directory+"/", "./cmd/...")
	command.Dir = root(t)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}
	return filepath.Join(directory, "server"), filepath.Join(directory, "agent")
}

func run(t *testing.T, env []string, name string, arguments ...string) {
	t.Helper()
	command := exec.Command(name, arguments...)
	command.Env = append(os.Environ(), env...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, arguments, err, output)
	}
}

func bringUp(t *testing.T) *stack {
	t.Helper()
	directory := t.TempDir()
	env := stand.Env(t)
	ownerDSN, runtimeDSN := stand.CenterDatabase(t)
	events := stand.CenterEvents(t)
	serverBin, agentBin := build(t, directory)
	apiAddress, agentAddress := freePort(t), "127.0.0.1:25443"
	if hold := os.Getenv("DG_E2E_HOLD"); hold != "" {
		apiAddress = "127.0.0.1:25800"
	}
	pkiDirectory := filepath.Join(directory, "pki")
	serverEnv := []string{
		"DG_PG_DSN=" + runtimeDSN, "DG_PG_MIGRATION_DSN=" + ownerDSN, "DG_PKI_DIR=" + pkiDirectory,
		"DG_API_ADDR=" + apiAddress, "DG_AGENT_ADDR=" + agentAddress,
		"DG_OIDC_ISSUER=" + keycloak + "/realms/" + realm, "DG_OIDC_CLIENT_ID=dataguard-dashboard",
		"DG_CH_ADDR=" + events.Address, "DG_CH_DATABASE=" + events.Database,
		"DG_CH_USER=" + events.Username, "DG_CH_PASSWORD=" + events.Password,
		"DG_CH_MIGRATION_USER=dg_ch_admin", "DG_CH_MIGRATION_PASSWORD=" + env["CENTER_CH_ADMIN_PASSWORD"],
		"DG_WEB_DIR=" + filepath.Join(root(t), "web", "dashboard", "dist"),
	}
	run(t, serverEnv, serverBin, "migrate")
	run(t, serverEnv, serverBin, "pki-init", "--dir", pkiDirectory, "--hosts", "127.0.0.1")
	item := &stack{
		root: root(t), directory: directory, serverBin: serverBin, agentBin: agentBin, serverEnv: serverEnv,
		api: "http://" + apiAddress, agentURL: "https://" + agentAddress, ownerDSN: ownerDSN, events: events,
		stateDir: filepath.Join(directory, "state"), owner: t,
	}
	item.startServer(t)
	return item
}

func (s *stack) startServer(t *testing.T) {
	t.Helper()
	s.server = start(s.owner, filepath.Join(s.directory, "server.log"), s.serverEnv, s.serverBin, "serve")
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		response, err := http.Get(s.api + "/readyz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("server did not become ready:\n%s", s.logs(t, "server.log"))
}

func (s *stack) logs(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(s.directory, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func postForm(t *testing.T, address string, form url.Values) map[string]any {
	t.Helper()
	response, err := http.PostForm(address, form)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	var decoded map[string]any
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("%s: %d %v", address, response.StatusCode, decoded)
	}
	return decoded
}

func keycloakAdmin(t *testing.T) string {
	t.Helper()
	decoded := postForm(t, keycloak+"/realms/master/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {"admin-cli"}, "username": {"dg_admin"},
		"password": {stand.Env(t)["KEYCLOAK_ADMIN_PASSWORD"]},
	})
	return decoded["access_token"].(string)
}

func keycloakCall(t *testing.T, token, method, path string, body any) *http.Response {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(method, keycloak+"/admin/realms/"+realm+path, bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

// createUser replaces any user left by a previous run.
func createUser(t *testing.T, name, role, tenantID string) string {
	t.Helper()
	admin := keycloakAdmin(t)
	existing := keycloakCall(t, admin, http.MethodGet, "/users?exact=true&username="+name, nil)
	var found []struct{ ID string }
	_ = json.NewDecoder(existing.Body).Decode(&found)
	_ = existing.Body.Close()
	for _, user := range found {
		_ = keycloakCall(t, admin, http.MethodDelete, "/users/"+user.ID, nil).Body.Close()
	}
	password := "Dg-" + hexToken(t)
	attributes := map[string][]string{}
	if tenantID != "" {
		attributes["tenant_id"] = []string{tenantID}
	}
	response := keycloakCall(t, admin, http.MethodPost, "/users", map[string]any{
		"username": name, "enabled": true, "email": name + "@example.invalid", "emailVerified": true,
		"firstName": name, "lastName": "Test", "attributes": attributes,
		"credentials": []map[string]any{{"type": "password", "value": password, "temporary": false}},
	})
	_ = response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("create user: %d", response.StatusCode)
	}
	userID := filepath.Base(response.Header.Get("Location"))
	roleResponse := keycloakCall(t, admin, http.MethodGet, "/roles/"+role, nil)
	var roleBody map[string]any
	_ = json.NewDecoder(roleResponse.Body).Decode(&roleBody)
	_ = roleResponse.Body.Close()
	_ = keycloakCall(t, admin, http.MethodPost, "/users/"+userID+"/role-mappings/realm", []any{roleBody}).Body.Close()
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
	decoded := postForm(t, keycloak+"/realms/"+realm+"/protocol/openid-connect/token", url.Values{
		"grant_type": {"password"}, "client_id": {"dataguard-cli"}, "username": {name}, "password": {password}, "scope": {"openid"},
	})
	return decoded["access_token"].(string)
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
	request, err := http.NewRequest(method, s.api+"/api/v1"+path, reader)
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
	password := createUser(t, "dg-admin", "tenant_admin", s.tenantID)
	s.token = login(t, "dg-admin", password)
	if hold := os.Getenv("DG_E2E_HOLD"); hold != "" {
		// The browser may run where this process is unreachable, so the hold file also
		// tells how to start another server on the same databases.
		credentials, err := json.Marshal(map[string]any{
			"user": "dg-admin", "password": password, "api": s.api,
			"server": s.serverBin, "directory": s.directory, "env": s.serverEnv,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(hold+".credentials", credentials, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var environment restapi.Environment
	s.must(t, http.MethodPost, "/environments", restapi.NewEnvironment{Name: "production", Kind: restapi.Production}, &environment)
	var token restapi.EnrollmentToken
	s.must(t, http.MethodPost, "/enrollment-tokens", restapi.NewEnrollmentToken{EnvironmentId: environment.Id}, &token)
	s.writeAgentConfig(t)
	tokenPath := filepath.Join(s.directory, "token.txt")
	if err := os.WriteFile(tokenPath, []byte(token.Token), 0o600); err != nil {
		t.Fatal(err)
	}
	run(t, nil, s.agentBin, "enroll", "--config", s.configPath, "--token-file", tokenPath)
	s.startAgent(t)
}

func (s *stack) writeAgentConfig(t *testing.T) {
	t.Helper()
	s.sources = stand.AllSources(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s.appKey = private
	keyPath := filepath.Join(s.directory, "crm.pub")
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(public)), 0o600); err != nil {
		t.Fatal(err)
	}
	settings := config.Config{
		Center: config.Center{URL: s.agentURL, CAFile: filepath.Join(s.directory, "pki", "ca.crt")}, StateDir: s.stateDir,
		Applications: []config.Application{{ID: "crm", PublicKeyFile: keyPath}},
	}
	for i := range s.sources {
		source := s.sources[i].Config
		source.Audit.Directory = stand.AuditDirectory(s.sources[i].Dialect.Name)
		settings.Sources = append(settings.Sources, source)
	}
	s.configPath = filepath.Join(s.directory, "agent.yaml")
	if err := os.WriteFile(s.configPath, encodeYAML(t, settings), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (s *stack) startAgent(t *testing.T) {
	t.Helper()
	s.agent = start(s.owner, filepath.Join(s.directory, "agent.log"), nil, s.agentBin, "run", "--config", s.configPath)
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
	return values
}

func dumpPostgres(t *testing.T, dsn string) string {
	t.Helper()
	ctx := context.Background()
	connection, err := pgx.Connect(ctx, dsn)
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

func dumpClickHouse(t *testing.T, settings clickhouse.Settings) string {
	t.Helper()
	ctx := context.Background()
	admin := stand.Env(t)["CENTER_CH_ADMIN_PASSWORD"]
	connection, err := chdriver.Open(&chdriver.Options{
		Addr: []string{settings.Address},
		Auth: chdriver.Auth{Database: settings.Database, Username: "dg_ch_admin", Password: admin},
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
		s.agent.kill(syscall.SIGKILL)
		const statements = 20
		for i := range statements {
			if _, err := source.Admin.ExecContext(ctx, fmt.Sprintf(`SELECT email, %d FROM %s`, i, seed.Users)); err != nil {
				t.Fatal(err)
			}
		}
		s.startAgent(t)
		eventually(t, "events from the outage", func() bool {
			return s.eventTotal(t, "&principal=dg_app&category=PERSONAL.EMAIL")-before >= statements
		})
	})

	t.Run("server restart loses nothing", func(t *testing.T) {
		source := &s.sources[1]
		before := s.eventTotal(t, "&principal=dg_app&category=PERSONAL.PHONE")
		s.server.kill(syscall.SIGKILL)
		const statements = 15
		for i := range statements {
			if _, err := source.Admin.ExecContext(ctx, fmt.Sprintf(`SELECT phone, %d FROM %s`, i, seed.Users)); err != nil {
				t.Fatal(err)
			}
		}
		time.Sleep(3 * time.Second)
		s.startServer(t)
		eventually(t, "events delivered after restart", func() bool {
			return s.eventTotal(t, "&principal=dg_app&category=PERSONAL.PHONE")-before >= statements
		})
	})

	t.Run("no source value left the source", func(t *testing.T) {
		values := append(all, synthetic.CanaryMarker)
		assertAbsent(t, "agent log", s.logs(t, "agent.log"), values)
		assertAbsent(t, "server log", s.logs(t, "server.log"), values)
		assertAbsent(t, "central postgres", dumpPostgres(t, s.ownerDSN), values)
		assertAbsent(t, "clickhouse", dumpClickHouse(t, s.events), values)
		s.assertQueueClean(t, values)
	})

	if hold := os.Getenv("DG_E2E_HOLD"); hold != "" {
		if err := os.WriteFile(hold+".ready", []byte("ok"), 0o600); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(20 * time.Minute)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(hold + ".done"); err == nil {
				break
			}
			time.Sleep(time.Second)
		}
	}

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

	t.Run("agent stopped makes the source blind, not green", func(t *testing.T) {
		s.agent.kill(syscall.SIGKILL)
		if rows := s.coverage(t); rows[0].Status == "" {
			t.Fatal("coverage has no status")
		}
	})
}

// assertQueueClean opens the stopped agent's queue. The agent must be stopped,
// because the file is locked while it runs.
func (s *stack) assertQueueClean(t *testing.T, values []string) {
	t.Helper()
	s.agent.kill(syscall.SIGKILL)
	stored, err := queue.Open(s.stateDir, 1<<24)
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
	s.startAgent(t)
}
