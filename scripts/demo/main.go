// Command demo brings the local stand to a filled dashboard: accounts, an
// organization, an enrolled agent, the four stand databases as sources,
// synthetic data, some access traffic and finished scans. Running it again
// keeps what exists, repairs what is missing and issues new passwords, which
// are printed once and stored only in Keycloak.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"dataguard/internal/agent/sources"
	"dataguard/internal/gen/restapi"
	"dataguard/internal/platform/sealing"
	"dataguard/internal/testkit/keycloak"
	"dataguard/internal/testkit/seed"
	"dataguard/internal/testkit/stand"
	"dataguard/internal/testkit/synthetic"
	"dataguard/sdk/go/appcontext"
)

const (
	dashboard       = "http://127.0.0.1:25800"
	api             = dashboard + "/api/v1"
	tenantName      = "Демо"
	environmentName = "production"
	agentVolume     = "dataguard-dev_agent-state"
	seededRows      = 200
	// An agent silent for longer is not the one running in the container.
	agentFresh = 2 * time.Minute
	poll       = time.Second
)

type account struct {
	name, role, description string
}

// The end-to-end test replaces its own users on every run, so the names differ.
var tenantAccounts = []account{
	{"demo-admin", "tenant_admin", "администратор организации «" + tenantName + "»: источники, агенты, сканы"},
	{"demo-analyst", "security_analyst", "аналитик организации «" + tenantName + "»: отчёты и сканы"},
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "demo:", err)
		os.Exit(1)
	}
}

func step(text string) { fmt.Fprintln(os.Stderr, "→", text) }

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	env, err := stand.ReadEnv()
	if err != nil {
		return err
	}

	step("Учётные записи и организация")
	tenant, passwords, err := accounts(ctx, env["KEYCLOAK_ADMIN_PASSWORD"])
	if err != nil {
		return err
	}
	center := newClient("demo-admin", passwords["demo-admin"])

	step("Агент")
	agent, err := ensureAgent(ctx, center)
	if err != nil {
		return err
	}

	step("Синтетические данные в базах стенда")
	databases, err := stand.OpenSources(env)
	if err != nil {
		return err
	}
	defer func() {
		for _, database := range databases {
			_ = database.Admin.Close()
		}
	}()
	if err := seedIfEmpty(ctx, databases); err != nil {
		return err
	}

	step("Источники")
	ids, err := ensureSources(ctx, center, tenant.Id, agent, stand.ContainerSources(env))
	if err != nil {
		return err
	}
	if err := waitConnected(ctx, center, ids); err != nil {
		return err
	}

	step("Обращения к данным")
	if err := waitObserving(ctx, center, ids); err != nil {
		return err
	}
	key, err := stand.ApplicationKey()
	if err != nil {
		return err
	}
	if err := traffic(ctx, databases, key); err != nil {
		return err
	}

	step("Сканирование")
	if err := scanAll(ctx, center, ids); err != nil {
		return err
	}
	return printSummary(passwords)
}

// accounts creates the platform administrator, the organization and its users.
// Every run issues new passwords.
func accounts(ctx context.Context, keycloakPassword string) (restapi.Tenant, map[string]string, error) {
	admin, err := keycloak.Connect(ctx, keycloakPassword)
	if err != nil {
		return restapi.Tenant{}, nil, err
	}
	passwords := map[string]string{}
	if passwords["platform"], err = admin.CreateUser(ctx, "platform", "platform_admin", ""); err != nil {
		return restapi.Tenant{}, nil, err
	}
	tenant, err := ensureTenant(ctx, newClient("platform", passwords["platform"]))
	if err != nil {
		return restapi.Tenant{}, nil, err
	}
	for _, item := range tenantAccounts {
		if passwords[item.name], err = admin.CreateUser(ctx, item.name, item.role, tenant.Id.String()); err != nil {
			return restapi.Tenant{}, nil, err
		}
	}
	return tenant, passwords, nil
}

// client calls the API as one user and signs in again before the token expires.
type client struct {
	username, password string

	mu       sync.Mutex
	token    string
	signedIn time.Time
}

func newClient(username, password string) *client {
	return &client{username: username, password: password}
}

func (c *client) bearer(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token == "" || time.Since(c.signedIn) > time.Minute {
		token, err := keycloak.Login(ctx, c.username, c.password)
		if err != nil {
			return "", err
		}
		c.token, c.signedIn = token, time.Now()
	}
	return c.token, nil
}

func (c *client) call(ctx context.Context, method, route string, body, into any) error {
	token, err := c.bearer(ctx)
	if err != nil {
		return err
	}
	var reader io.Reader = http.NoBody
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, api+route, reader)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		return fmt.Errorf("server is not reachable, run make dev-up: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode >= http.StatusMultipleChoices {
		var problem restapi.Problem
		_ = json.NewDecoder(response.Body).Decode(&problem)
		return fmt.Errorf("%s %s: %d %s", method, route, response.StatusCode, problem.Message)
	}
	if into == nil {
		return nil
	}
	return json.NewDecoder(response.Body).Decode(into)
}

func ensureTenant(ctx context.Context, platform *client) (restapi.Tenant, error) {
	var tenants []restapi.Tenant
	if err := platform.call(ctx, http.MethodGet, "/tenants", nil, &tenants); err != nil {
		return restapi.Tenant{}, err
	}
	if index := slices.IndexFunc(tenants, func(t restapi.Tenant) bool { return t.Name == tenantName }); index >= 0 {
		return tenants[index], nil
	}
	var created restapi.Tenant
	err := platform.call(ctx, http.MethodPost, "/tenants", restapi.NewTenant{Name: tenantName}, &created)
	return created, err
}

func ensureEnvironment(ctx context.Context, center *client) (restapi.Environment, error) {
	var environments []restapi.Environment
	if err := center.call(ctx, http.MethodGet, "/environments", nil, &environments); err != nil {
		return restapi.Environment{}, err
	}
	if index := slices.IndexFunc(environments, func(e restapi.Environment) bool { return e.Name == environmentName }); index >= 0 {
		return environments[index], nil
	}
	var created restapi.Environment
	err := center.call(ctx, http.MethodPost, "/environments",
		restapi.NewEnvironment{Name: environmentName, Kind: restapi.Production}, &created)
	return created, err
}

// ensureAgent keeps the agent container if it already serves this
// organization. Otherwise it enrolls it again from an empty state, the only way
// an agent may enroll, and revokes the organization's agents that went silent.
func ensureAgent(ctx context.Context, center *client) (restapi.Agent, error) {
	var agents []restapi.Agent
	if err := center.call(ctx, http.MethodGet, "/agents", nil, &agents); err != nil {
		return restapi.Agent{}, err
	}
	running, err := compose(ctx, nil, "ps", "--status", "running", "--quiet", "agent")
	if err != nil {
		return restapi.Agent{}, err
	}
	if index := slices.IndexFunc(agents, serving); index >= 0 && strings.TrimSpace(running) != "" {
		return agents[index], nil
	}
	for _, agent := range agents {
		if agent.Status == restapi.AgentStatusActive {
			if err := center.call(ctx, http.MethodPost, "/agents/"+agent.Id.String()+"/revoke", nil, nil); err != nil {
				return restapi.Agent{}, err
			}
		}
	}
	environment, err := ensureEnvironment(ctx, center)
	if err != nil {
		return restapi.Agent{}, err
	}
	var token restapi.EnrollmentToken
	if err := center.call(ctx, http.MethodPost, "/enrollment-tokens", restapi.NewEnrollmentToken{EnvironmentId: environment.Id}, &token); err != nil {
		return restapi.Agent{}, err
	}
	if err := enrollFromScratch(ctx, token.Token); err != nil {
		return restapi.Agent{}, err
	}
	return awaitNewAgent(ctx, center, agents)
}

// serving is an agent that can open sealed passwords and reported in lately.
func serving(agent restapi.Agent) bool {
	return agent.Status == restapi.AgentStatusActive && agent.SealingPublicKey != nil && agent.LastSeenAt != nil &&
		time.Since(*agent.LastSeenAt) < agentFresh
}

// enrollFromScratch drops the agent container with its state, enrolls it with
// token and starts it.
func enrollFromScratch(ctx context.Context, token string) error {
	if _, err := compose(ctx, nil, "rm", "--stop", "--force", "agent"); err != nil {
		return err
	}
	if output, err := exec.CommandContext(ctx, "docker", "volume", "rm", "--force", agentVolume).CombinedOutput(); err != nil {
		return fmt.Errorf("remove agent state: %w: %s", err, output)
	}
	if _, err := compose(ctx, strings.NewReader(token), "run", "--rm", "--no-deps", "-T", "agent",
		"enroll", "--config", "/etc/dataguard/agent.yaml", "--token-file", "/dev/stdin"); err != nil {
		return err
	}
	_, err := compose(ctx, nil, "up", "--detach", "--no-deps", "agent")
	return err
}

// awaitNewAgent waits for an agent the center did not list before to report in.
func awaitNewAgent(ctx context.Context, center *client, before []restapi.Agent) (restapi.Agent, error) {
	known := make(map[uuid.UUID]bool, len(before))
	for _, agent := range before {
		known[agent.Id] = true
	}
	var enrolled restapi.Agent
	err := until(ctx, "the agent reports in", func() (bool, error) {
		var current []restapi.Agent
		if err := center.call(ctx, http.MethodGet, "/agents", nil, &current); err != nil {
			return false, err
		}
		for _, agent := range current {
			if !known[agent.Id] && agent.LastSeenAt != nil {
				enrolled = agent
				return true, nil
			}
		}
		return false, nil
	})
	return enrolled, err
}

func seedIfEmpty(ctx context.Context, databases []stand.Source) error {
	for i, database := range databases {
		var rows int
		err := database.Admin.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+seed.Users).Scan(&rows)
		if err == nil && rows > 0 {
			continue
		}
		if err := seed.Tables(ctx, database.Admin, database.Dialect, seededRows, synthetic.New(uint64(i)+1)); err != nil {
			return fmt.Errorf("seed %s: %w", database.Dialect.Name, err)
		}
	}
	return nil
}

// ensureSources defines the stand databases for the agent. A source bound to
// another agent cannot serve this one: its password is sealed to that agent.
func ensureSources(ctx context.Context, center *client, tenantID uuid.UUID, agent restapi.Agent, wanted []sources.Definition) ([]uuid.UUID, error) {
	var existing []restapi.Source
	if err := center.call(ctx, http.MethodGet, "/sources", nil, &existing); err != nil {
		return nil, err
	}
	ids := make([]uuid.UUID, 0, len(wanted))
	for _, item := range wanted {
		index := slices.IndexFunc(existing, func(s restapi.Source) bool { return s.Key == item.Name })
		if index >= 0 && existing[index].AgentId == agent.Id {
			ids = append(ids, existing[index].Id)
			continue
		}
		if index >= 0 {
			if err := center.call(ctx, http.MethodDelete, "/sources/"+existing[index].Id.String(), nil, nil); err != nil {
				return nil, err
			}
		}
		sealed, err := sealing.Seal(*agent.SealingPublicKey, sealing.Binding{
			TenantID: tenantID, AgentID: agent.Id, Engine: item.Engine, Host: item.Host, Port: item.Port,
			Database: item.Database, Username: item.Username, TLS: item.TLS,
		}, []byte(item.Password))
		if err != nil {
			return nil, err
		}
		var created restapi.Source
		if err := center.call(ctx, http.MethodPost, "/sources", restapi.NewSource{
			Name: item.Name, AgentId: agent.Id, Engine: restapi.SourceEngine(item.Engine), Host: item.Host,
			Port: item.Port, Database: item.Database, Username: item.Username, Tls: restapi.TlsMode(item.TLS),
			AuditDirectory: &item.AuditDirectory, SealedPassword: sealed,
		}, &created); err != nil {
			return nil, err
		}
		ids = append(ids, created.Id)
	}
	return ids, nil
}

func waitConnected(ctx context.Context, center *client, ids []uuid.UUID) error {
	return until(ctx, "the agent connects to every source", func() (bool, error) {
		var listed []restapi.Source
		if err := center.call(ctx, http.MethodGet, "/sources", nil, &listed); err != nil {
			return false, err
		}
		for _, id := range ids {
			index := slices.IndexFunc(listed, func(s restapi.Source) bool { return s.Id == id })
			if index < 0 || listed[index].ProbedAt == nil {
				return false, nil
			}
			if code := listed[index].StatusCode; code != "" {
				return false, fmt.Errorf("source %s: the agent reports %s", listed[index].Key, code)
			}
		}
		return true, nil
	})
}

// waitObserving matters because collection starts at the end of each log:
// queries made before that are not audited, by design.
func waitObserving(ctx context.Context, center *client, ids []uuid.UUID) error {
	return until(ctx, "audit collection starts on every source", func() (bool, error) {
		var rows []restapi.CoverageRow
		if err := center.call(ctx, http.MethodGet, "/audit/coverage", nil, &rows); err != nil {
			return false, err
		}
		for _, id := range ids {
			index := slices.IndexFunc(rows, func(r restapi.CoverageRow) bool { return r.SourceId == id })
			if index < 0 || rows[index].Status != restapi.OBSERVING {
				return false, nil
			}
		}
		return true, nil
	})
}

// traffic runs the kind of queries an application makes, so the access pages
// have something to show: plain reads, a failing one, and in PostgreSQL reads
// on behalf of employees whose identity the application signs.
func traffic(ctx context.Context, databases []stand.Source, key ed25519.PrivateKey) error {
	statements := []string{
		"SELECT email, phone FROM " + seed.Users + " WHERE id <= 3",
		"SELECT inn, snils FROM " + seed.Users + " WHERE id = 1",
		"SELECT card_number FROM " + seed.Users + " WHERE id = 2",
		"SELECT external_ref FROM " + seed.Orders + " WHERE id <= 5",
	}
	for _, database := range databases {
		for _, statement := range statements {
			if _, err := database.Admin.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("%s: %w", database.Dialect.Name, err)
			}
		}
		// A failed query shows up as such where the engine records the outcome.
		_, _ = database.Admin.ExecContext(ctx, "SELECT no_such_column FROM "+seed.Users) //nolint:gosec // The table name is a constant of the seed.
	}
	signer := appcontext.NewSigner("crm", key)
	for _, employee := range []string{"employee-123", "employee-456"} {
		if err := signedRead(ctx, databases[0].Admin, signer, employee); err != nil {
			return err
		}
	}
	return nil
}

func signedRead(ctx context.Context, database *sql.DB, signer *appcontext.Signer, employee string) error {
	token, err := signer.Token(employee, "dg_app", "")
	if err != nil {
		return err
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := appcontext.Apply(ctx, tx, token); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "SELECT email, passport FROM "+seed.Users+" WHERE id <= 2"); err != nil { //nolint:gosec // The table name is a constant of the seed.
		return err
	}
	return tx.Commit()
}

func scanAll(ctx context.Context, center *client, ids []uuid.UUID) error {
	jobs := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		var job restapi.Scan
		if err := center.call(ctx, http.MethodPost, "/scans", restapi.NewScan{SourceId: id}, &job); err != nil {
			return err
		}
		jobs = append(jobs, job.Id)
	}
	return until(ctx, "scans finish", func() (bool, error) {
		var scans []restapi.Scan
		if err := center.call(ctx, http.MethodGet, "/scans", nil, &scans); err != nil {
			return false, err
		}
		for _, id := range jobs {
			index := slices.IndexFunc(scans, func(s restapi.Scan) bool { return s.Id == id })
			if index < 0 {
				return false, nil
			}
			switch scans[index].Status {
			case restapi.Completed, restapi.Partial:
			case restapi.Failed, restapi.Cancelled:
				return false, fmt.Errorf("scan %s: %s", id, scans[index].FailureCode)
			default:
				return false, nil
			}
		}
		return true, nil
	})
}

func until(ctx context.Context, what string, done func() (bool, error)) error {
	for {
		finished, err := done()
		if err != nil || finished {
			return err
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting until %s", what)
		case <-time.After(poll):
		}
	}
}

func compose(ctx context.Context, stdin io.Reader, arguments ...string) (string, error) {
	root := filepath.Join(stand.DevDirectory(), "..", "..")
	base := []string{
		"compose", "--project-name", "dataguard-dev", "--env-file", "deployments/dev/.env",
		"-f", "deployments/dev/compose.yml", "--profile", "agent",
	}
	command := exec.CommandContext(ctx, "docker", append(base, arguments...)...) //nolint:gosec // Arguments are fixed in this file.
	command.Dir = root
	command.Stdin = stdin
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err != nil {
		return "", errors.Join(fmt.Errorf("docker compose %s", strings.Join(arguments, " ")), err, errors.New(stderr.String()))
	}
	return stdout.String(), nil
}

func printSummary(passwords map[string]string) error {
	var lines strings.Builder
	fmt.Fprintf(&lines, "\nГотово. Dashboard: %s\n\n%-14s %-30s %s\n", dashboard, "Логин", "Пароль", "Кто это")
	fmt.Fprintf(&lines, "%-14s %-30s %s\n", "platform", passwords["platform"], "администратор платформы: заводит организации, данных не видит")
	for _, item := range tenantAccounts {
		fmt.Fprintf(&lines, "%-14s %-30s %s\n", item.name, passwords[item.name], item.description)
	}
	lines.WriteString("\nПароли выданы заново и больше нигде не записаны. Повторный запуск выдаст новые.\n")
	_, err := os.Stdout.WriteString(lines.String())
	return err
}
