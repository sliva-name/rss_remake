//go:build install

// Package install_test installs the center from deployments/production the way
// INSTALL.md tells an operator to, on this machine but apart from the stand:
// its own compose project, ports, settings, passwords and certificates. Then it
// enrolls an agent from deployments/agent, backs the center up, changes it,
// restores it and checks that nothing a person typed is visible in the Docker API.
package install_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"dataguard/internal/gen/restapi"
	"dataguard/internal/testkit/keycloak"
)

const (
	project      = "dataguard-install-test"
	agentProject = "dataguard-install-test-agent"
	host         = "dataguard.test"
	// Apart from the stand's 25xxx ports, so both can run at once.
	dashboardPort = "25643"
	agentPort     = "25644"
	keycloakPort  = "25645"
	wait          = 3 * time.Minute
)

func repository(t *testing.T) string {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func run(t *testing.T, stdin io.Reader, env []string, name string, arguments ...string) string {
	t.Helper()
	command := exec.CommandContext(context.WithoutCancel(t.Context()), name, arguments...)
	command.Dir = repository(t)
	command.Env = append(os.Environ(), env...)
	command.Stdin = stdin
	var output bytes.Buffer
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(arguments, " "), err, output.String())
	}
	return output.String()
}

// writeCertificates plays the customer's CA: it issues the dashboard's
// certificate for the host people open, and the identity provider uses it too.
func writeCertificates(t *testing.T, directory string) *x509.CertPool {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Install test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true, IsCA: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caKey.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: host},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{host},
	}, ca, key.Public(), caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), caPEM...)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		"dashboard.crt": chain,
		"dashboard.key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		"oidc-ca.crt":   caPEM,
	} {
		if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	return roots
}

// browser reaches the installation as a person would: by its host name, which
// resolves here to this machine, trusting the customer's CA.
func browser(roots *x509.CertPool) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			_, port, _ := net.SplitHostPort(address)
			return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
		},
	}}
}

type installation struct {
	directory string
	client    *http.Client
	token     string
}

func (i *installation) compose(t *testing.T, stdin io.Reader, arguments ...string) string {
	t.Helper()
	base := []string{"compose", "--project-name", project, "--env-file", filepath.Join(i.directory, ".env"),
		"-f", "deployments/production/compose.yml", "--profile", "keycloak"}
	return run(t, stdin, nil, "docker", append(base, arguments...)...)
}

func (i *installation) api(t *testing.T, method, path string, body, into any) int {
	t.Helper()
	var reader io.Reader = http.NoBody
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(t.Context(), method, "https://"+host+":"+dashboardPort+"/api/v1"+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+i.token)
	request.Header.Set("Content-Type", "application/json")
	response, err := i.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if into != nil && response.StatusCode < http.StatusMultipleChoices {
		if err := json.NewDecoder(response.Body).Decode(into); err != nil {
			t.Fatal(err)
		}
	}
	return response.StatusCode
}

func (i *installation) must(t *testing.T, method, path string, body, into any) {
	t.Helper()
	if status := i.api(t, method, path, body, into); status >= http.StatusMultipleChoices {
		t.Fatalf("%s %s: %d", method, path, status)
	}
}

func eventually(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(wait)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out: %s", what)
		}
		time.Sleep(time.Second)
	}
}

func TestInstallFromScratch(t *testing.T) {
	ctx := t.Context()
	repo := repository(t)
	// The images of this checkout; an installation pulls released ones.
	run(t, nil, nil, "docker", "build", "--target", "server", "-t", "dataguard/server:install-test", ".")
	run(t, nil, nil, "docker", "build", "--target", "agent", "-t", "dataguard/agent:install-test", ".")

	// The machine: settings, passwords, certificates and backups in one place.
	directory := t.TempDir()
	i := &installation{directory: directory, client: browser(writeCertificates(t, filepath.Join(directory, "tls")))}
	settings := strings.Join([]string{
		"DG_VERSION=install-test",
		"DG_PUBLIC_URL=https://" + host + ":" + dashboardPort,
		"DG_DASHBOARD_PORT=" + dashboardPort,
		"DG_AGENT_HOSTS=" + host + ",host.docker.internal",
		"DG_AGENT_PORT=" + agentPort,
		"DG_SECRETS_DIR=" + filepath.Join(directory, "secrets"),
		"DG_TLS_DIR=" + filepath.Join(directory, "tls"),
		"DG_BACKUP_DIR=" + filepath.Join(directory, "backup"),
		"DG_OIDC_ISSUER=https://" + host + ":" + keycloakPort + "/realms/dataguard",
		"DG_OIDC_CLIENT_ID=dataguard-dashboard",
		"DG_OIDC_CA_FILE=/run/secrets/oidc_ca",
		"DG_PUBLIC_HOST=" + host,
		"DG_KEYCLOAK_PORT=" + keycloakPort,
		"DG_KEYCLOAK_URL=https://" + host + ":" + keycloakPort,
		"DG_BROKER_REPLICATION=1",
		"DG_BROKER_CPUS=1",
		"DG_BROKER_MEMORY=1G",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(directory, ".env"), []byte(settings), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(directory, "backup"), 0o700); err != nil {
		t.Fatal(err)
	}
	run(t, nil, []string{"DG_ENV_FILE=" + filepath.Join(directory, ".env")}, filepath.Join(repo, "deployments/production/prepare.sh"))
	t.Cleanup(func() { i.compose(t, nil, "--profile", "backup", "down", "--volumes", "--remove-orphans") })
	started := time.Now()
	i.compose(t, nil, "up", "--detach", "--wait")
	t.Logf("center up in %s", time.Since(started).Round(time.Second))

	// The identity provider: an account per role, as an administrator would.
	keycloakPassword, err := os.ReadFile(filepath.Join(directory, "secrets", "keycloak_admin_password"))
	if err != nil {
		t.Fatal(err)
	}
	idp := keycloak.Server{BaseURL: "https://" + host + ":" + keycloakPort, HTTP: i.client}
	admin, err := idp.Connect(ctx, string(keycloakPassword))
	if err != nil {
		t.Fatal(err)
	}
	if err := admin.AddPasswordClient(ctx); err != nil {
		t.Fatal(err)
	}
	signIn := func(name, role, tenantID string) string {
		t.Helper()
		password, err := admin.CreateUser(ctx, name, role, tenantID)
		if err != nil {
			t.Fatal(err)
		}
		token, err := idp.Login(ctx, name, password)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}

	i.token = signIn("platform", "platform_admin", "")
	var tenant restapi.Tenant
	i.must(t, http.MethodPost, "/tenants", map[string]string{"name": "Acme"}, &tenant)
	i.token = signIn("acme-admin", "tenant_admin", tenant.Id.String())
	var environment restapi.Environment
	i.must(t, http.MethodPost, "/environments", map[string]string{"name": "Production", "kind": "production"}, &environment)
	var enrollment restapi.EnrollmentToken
	i.must(t, http.MethodPost, "/enrollment-tokens", map[string]string{"environmentId": environment.Id.String()}, &enrollment)

	// The agent on another host: the CA certificate copied from the center, its
	// own settings, enrollment with the token on standard input.
	caCertificate := i.compose(t, nil, "--profile", "backup", "run", "--rm", "--no-deps", "-T", "--entrypoint", "cat", "backup", "/pki/ca.crt")
	agentDirectory := t.TempDir()
	agentFiles := map[string]string{
		"ca.crt": caCertificate,
		"agent.yaml": "center:\n  url: https://host.docker.internal:" + agentPort + "\n  ca_file: /etc/dataguard/ca/ca.crt\n" +
			"state_dir: /var/lib/dataguard\nallowed:\n  hosts: [db.invalid]\n  audit_directories: [/var/log/none]\n",
		// The test's addition: this machine stands in for the center's host.
		"override.yml": "services:\n  agent:\n    extra_hosts: [\"host.docker.internal:host-gateway\"]\n    volumes:\n" +
			"      - " + filepath.Join(agentDirectory, "agent.yaml") + ":/etc/dataguard/agent.yaml:ro\n" +
			"      - " + filepath.Join(agentDirectory, "ca.crt") + ":/etc/dataguard/ca/ca.crt:ro\n",
	}
	for name, content := range agentFiles {
		if err := os.WriteFile(filepath.Join(agentDirectory, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	agent := func(stdin io.Reader, arguments ...string) string {
		t.Helper()
		base := []string{"compose", "--project-name", agentProject, "-f", "deployments/agent/compose.yml",
			"-f", filepath.Join(agentDirectory, "override.yml")}
		return run(t, stdin, []string{"DG_VERSION=install-test"}, "docker", append(base, arguments...)...)
	}
	t.Cleanup(func() { agent(nil, "down", "--volumes") })
	agent(strings.NewReader(enrollment.Token), "run", "--rm", "-T", "agent", "enroll", "--config", "/etc/dataguard/agent.yaml", "--token-file", "/dev/stdin")
	agent(nil, "up", "--detach")
	lastSeen := func() time.Time {
		var agents []restapi.Agent
		i.must(t, http.MethodGet, "/agents", nil, &agents)
		if len(agents) != 1 || agents[0].LastSeenAt == nil || agents[0].Status != restapi.AgentStatusActive {
			return time.Time{}
		}
		return *agents[0].LastSeenAt
	}
	eventually(t, "the agent reports to the center", func() bool { return !lastSeen().IsZero() })

	// Backup, a change after it, restore: the change is gone, the agent stays.
	i.compose(t, nil, "--profile", "backup", "run", "--rm", "--no-deps", "backup", "backup")
	i.must(t, http.MethodPost, "/environments", map[string]string{"name": "After the backup", "kind": "testing"}, nil)
	i.compose(t, nil, "stop", "server")
	i.compose(t, nil, "--profile", "backup", "run", "--rm", "--no-deps", "backup", "restore")
	i.compose(t, nil, "up", "--detach", "--wait")
	restoredAt := time.Now()
	var environments []restapi.Environment
	i.must(t, http.MethodGet, "/environments", nil, &environments)
	if len(environments) != 1 || environments[0].Name != "Production" {
		t.Fatalf("restored environments: %+v", environments)
	}
	eventually(t, "the agent reports to the restored center", func() bool { return lastSeen().After(restoredAt) })

	// Replacing the policy key, as INSTALL.md does it: the agent follows.
	i.compose(t, nil, "run", "--rm", "--no-deps", "pki-init", "rotate-policy-key", "--dir", "/var/lib/dataguard/pki")
	i.compose(t, nil, "restart", "server")
	i.compose(t, nil, "up", "--detach", "--wait")
	eventually(t, "the agent takes the new policy key", func() bool {
		var agents []restapi.Agent
		return i.api(t, http.MethodGet, "/agents", nil, &agents) == http.StatusOK && len(agents) == 1 && agents[0].PolicyKeyEpoch == 2
	})

	// What the Docker API shows of the installation carries no password.
	containers := strings.Fields(i.compose(t, nil, "ps", "--all", "--quiet"))
	inspected := run(t, nil, nil, "docker", append([]string{"inspect"}, containers...)...)
	secrets, err := os.ReadDir(filepath.Join(directory, "secrets"))
	if err != nil || len(secrets) == 0 {
		t.Fatalf("secrets: %v", err)
	}
	for _, secret := range secrets {
		value, err := os.ReadFile(filepath.Join(directory, "secrets", secret.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(inspected, string(value)) {
			t.Errorf("docker inspect shows %s", secret.Name())
		}
	}
}
