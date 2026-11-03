// Command devusers creates dashboard accounts on the local stand: a platform
// administrator, an organization and its users. Each run issues new passwords
// and prints them; they are stored only in Keycloak.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"dataguard/internal/gen/restapi"
	"dataguard/internal/testkit/keycloak"
)

const (
	envFile    = "deployments/dev/.env"
	api        = "http://127.0.0.1:25800/api/v1"
	tenantName = "Демо"
)

type account struct {
	name, role, description string
}

// Names differ from the end-to-end test's, which replaces its own users on every run.
var tenantAccounts = []account{
	{"demo-admin", "tenant_admin", "администратор организации «" + tenantName + "»"},
	{"demo-analyst", "security_analyst", "аналитик организации «" + tenantName + "»"},
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "devusers:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	adminPassword, err := readEnv("KEYCLOAK_ADMIN_PASSWORD")
	if err != nil {
		return err
	}
	admin, err := keycloak.Connect(ctx, adminPassword)
	if err != nil {
		return err
	}
	platformPassword, err := admin.CreateUser(ctx, "platform", "platform_admin", "")
	if err != nil {
		return err
	}
	token, err := keycloak.Login(ctx, "platform", platformPassword)
	if err != nil {
		return err
	}
	tenant, err := demoTenant(ctx, token)
	if err != nil {
		return err
	}
	var lines strings.Builder
	fmt.Fprintf(&lines, "Dashboard: http://127.0.0.1:25800\n\n%-14s %-30s %s\n", "Логин", "Пароль", "Кто это")
	fmt.Fprintf(&lines, "%-14s %-30s %s\n", "platform", platformPassword, "администратор платформы: заводит организации, данных не видит")
	for _, item := range tenantAccounts {
		password, err := admin.CreateUser(ctx, item.name, item.role, tenant.Id.String())
		if err != nil {
			return err
		}
		fmt.Fprintf(&lines, "%-14s %-30s %s\n", item.name, password, item.description)
	}
	_, err = os.Stdout.WriteString(lines.String())
	return err
}

// demoTenant returns the demo organization, creating it on the first run.
func demoTenant(ctx context.Context, token string) (restapi.Tenant, error) {
	var tenants []restapi.Tenant
	if err := callAPI(ctx, token, http.MethodGet, "/tenants", nil, &tenants); err != nil {
		return restapi.Tenant{}, err
	}
	for _, tenant := range tenants {
		if tenant.Name == tenantName {
			return tenant, nil
		}
	}
	var created restapi.Tenant
	err := callAPI(ctx, token, http.MethodPost, "/tenants", restapi.NewTenant{Name: tenantName}, &created)
	return created, err
}

func callAPI(ctx context.Context, token, method, route string, body, into any) error {
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
		return fmt.Errorf("%s %s: status %d", method, route, response.StatusCode)
	}
	return json.NewDecoder(response.Body).Decode(into)
}

func readEnv(name string) (string, error) {
	handle, err := os.Open(envFile)
	if err != nil {
		return "", fmt.Errorf("stand is not configured, run make dev-up: %w", err)
	}
	defer func() { _ = handle.Close() }()
	scanner := bufio.NewScanner(handle)
	for scanner.Scan() {
		if key, value, found := strings.Cut(scanner.Text(), "="); found && key == name {
			return value, nil
		}
	}
	return "", fmt.Errorf("%s is not in %s", name, envFile)
}
