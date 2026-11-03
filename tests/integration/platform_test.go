//go:build integration

package integration_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	"dataguard/internal/agent/center"
	"dataguard/internal/agent/config"
	"dataguard/internal/agent/identity"
	"dataguard/internal/agent/runtime"
	"dataguard/internal/contract/egress"
	"dataguard/internal/core/fleet"
	"dataguard/internal/core/tenant"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/gen/dataguard/agent/v1/agentv1connect"
	"dataguard/internal/platform/pki"
	"dataguard/internal/platform/safelog"
	"dataguard/internal/server/api"
	"dataguard/internal/server/app"
	"dataguard/internal/server/storage/postgres"
	"dataguard/internal/testkit/stand"
)

type staticAuthenticator map[string]api.Principal

func (a staticAuthenticator) Authenticate(_ context.Context, token string) (api.Principal, error) {
	principal, ok := a[token]
	if !ok {
		return api.Principal{}, errors.New("unknown token")
	}
	return principal, nil
}

type platform struct {
	app      *app.App
	agents   *httptest.Server
	rest     *httptest.Server
	caFile   string
	pkiDir   string
	authn    staticAuthenticator
	store    *postgres.Store
	ownerDSN string
}

func startPlatform(t *testing.T) *platform {
	t.Helper()
	ctx := context.Background()
	ownerDSN, runtimeDSN := stand.CenterDatabase(t)
	store, err := postgres.Open(ctx, runtimeDSN)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(store.Close)

	pkiDir := t.TempDir()
	if err := pki.Bootstrap(pkiDir, []string{"127.0.0.1"}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	authn := staticAuthenticator{}
	application, err := app.Build(app.Options{
		Store: store, PKIDirectory: pkiDir, CertificateTTL: time.Hour,
		Authenticator: authn, Logger: safelog.Discard(),
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	tlsConfig, err := app.AgentTLSConfig(pkiDir)
	if err != nil {
		t.Fatalf("AgentTLSConfig: %v", err)
	}
	agents := httptest.NewUnstartedServer(application.AgentHandler)
	agents.TLS = tlsConfig
	agents.EnableHTTP2 = true
	agents.StartTLS()
	t.Cleanup(agents.Close)

	rest := httptest.NewServer(application.APIHandler)
	t.Cleanup(rest.Close)

	return &platform{
		app: application, agents: agents, rest: rest, pkiDir: pkiDir, authn: authn,
		store: store, ownerDSN: ownerDSN,
		caFile: filepath.Join(pkiDir, pki.CACertFile),
	}
}

func (p *platform) newTenant(t *testing.T, name string) (tenant.Tenant, tenant.Environment) {
	t.Helper()
	ctx := context.Background()
	created, err := p.app.Tenants.CreateTenant(ctx, name)
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	environment, err := p.app.Tenants.CreateEnvironment(ctx, created.ID, "prod", tenant.KindProduction)
	if err != nil {
		t.Fatalf("CreateEnvironment: %v", err)
	}
	return created, environment
}

type enrolledAgent struct {
	client *center.Client
	store  *identity.Store
	dir    string
}

func (p *platform) enroll(t *testing.T, tenantID, environmentID uuid.UUID) enrolledAgent {
	t.Helper()
	ctx := context.Background()
	token, _, err := p.app.Fleet.CreateEnrollmentToken(ctx, tenantID, environmentID)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	dir := t.TempDir()
	settings := &config.Config{StateDir: dir, Center: config.Center{URL: p.agents.URL, CAFile: p.caFile}}
	if err := runtime.Enroll(ctx, settings, token, "1.0.0"); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	store, err := identity.Open(dir)
	if err != nil {
		t.Fatalf("identity.Open: %v", err)
	}
	client, err := center.New(p.agents.URL, p.caFile, store)
	if err != nil {
		t.Fatalf("center.New: %v", err)
	}
	return enrolledAgent{client: client, store: store, dir: dir}
}

func TestRuntimeRoleMustNotBypassRowSecurity(t *testing.T) {
	ownerDSN, _ := stand.CenterDatabase(t)
	if store, err := postgres.Open(context.Background(), ownerDSN); err == nil {
		store.Close()
		t.Fatal("a role that bypasses row security must be refused at startup")
	}
}

func TestAgentLifecycle(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	agent := platform.enroll(t, created.ID, environment.ID)

	if _, err := agent.client.Heartbeat(ctx, &agentv1.HeartbeatRequest{AgentVersion: "1.0.1"}); err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	reports := []*agentv1.SourceReport{{
		SourceKey: "crm", Engine: agentv1.Engine_ENGINE_POSTGRESQL, EngineVersion: "17.6",
		Capabilities: []*agentv1.CapabilityStatus{{
			Capability: agentv1.Capability_CAPABILITY_RETURNED_ROWS,
			Support:    agentv1.Support_SUPPORT_UNAVAILABLE,
			ReasonCode: "NATIVE_AUDIT_HAS_NO_ROW_COUNT",
		}},
	}}
	first, err := agent.client.ReportSources(ctx, reports)
	if err != nil {
		t.Fatalf("ReportSources: %v", err)
	}
	second, err := agent.client.ReportSources(ctx, reports)
	if err != nil {
		t.Fatalf("second ReportSources: %v", err)
	}
	if first.GetAssignments()[0].GetSourceId() != second.GetAssignments()[0].GetSourceId() {
		t.Fatal("a known source key must keep its id")
	}

	sources, err := platform.app.Fleet.ListSources(ctx, created.ID)
	if err != nil {
		t.Fatalf("ListSources: %v", err)
	}
	if len(sources) != 1 || len(sources[0].Capabilities) != 1 ||
		sources[0].Capabilities[0].Support != "SUPPORT_UNAVAILABLE" {
		t.Fatalf("unexpected sources: %+v", sources)
	}
	agents, err := platform.app.Fleet.ListAgents(ctx, created.ID)
	if err != nil {
		t.Fatalf("ListAgents: %v", err)
	}
	if len(agents) != 1 || agents[0].Version != "1.0.1" || agents[0].LastSeenAt == nil {
		t.Fatalf("heartbeat not recorded: %+v", agents)
	}
}

func TestEnrollmentTokenWorksOnce(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	token, _, err := platform.app.Fleet.CreateEnrollmentToken(ctx, created.ID, environment.ID)
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	settings := &config.Config{StateDir: t.TempDir(), Center: config.Center{URL: platform.agents.URL, CAFile: platform.caFile}}
	if err := runtime.Enroll(ctx, settings, token, "1.0.0"); err != nil {
		t.Fatalf("first Enroll: %v", err)
	}
	err = runtime.Enroll(ctx, settings, token, "1.0.0")
	if connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("second Enroll: %v", err)
	}
}

func TestRevokedAgentIsRefusedImmediately(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	agent := platform.enroll(t, created.ID, environment.ID)

	if err := platform.app.Fleet.Revoke(ctx, created.ID, agent.store.AgentID()); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err := agent.client.Heartbeat(ctx, &agentv1.HeartbeatRequest{})
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("Heartbeat after revoke: %v", err)
	}
}

func rawClient(t *testing.T, platform *platform, certificate *tls.Certificate) agentv1connect.AgentServiceClient {
	t.Helper()
	caPEM, err := os.ReadFile(platform.caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	config := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
	if certificate != nil {
		config.Certificates = []tls.Certificate{*certificate}
	}
	return agentv1connect.NewAgentServiceClient(
		&http.Client{Transport: &http.Transport{TLSClientConfig: config, ForceAttemptHTTP2: true}},
		platform.agents.URL)
}

func TestAgentServiceRequiresPlatformCertificate(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)

	t.Run("no certificate", func(t *testing.T) {
		_, err := rawClient(t, platform, nil).Heartbeat(ctx, connect.NewRequest(&agentv1.HeartbeatRequest{}))
		if connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("certificate from a foreign CA", func(t *testing.T) {
		foreignDir := t.TempDir()
		if err := pki.Bootstrap(foreignDir, []string{"127.0.0.1"}); err != nil {
			t.Fatal(err)
		}
		authority, err := pki.LoadAuthority(filepath.Join(foreignDir, pki.CACertFile), filepath.Join(foreignDir, pki.CAKeyFile), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		csr, key, err := pki.NewCSR()
		if err != nil {
			t.Fatal(err)
		}
		certificatePEM, _, err := authority.IssueAgentCertificate(csr, pki.Identity{TenantID: uuid.New(), AgentID: uuid.New()})
		if err != nil {
			t.Fatal(err)
		}
		certificate, err := tls.X509KeyPair(certificatePEM, key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = rawClient(t, platform, &certificate).Heartbeat(ctx, connect.NewRequest(&agentv1.HeartbeatRequest{}))
		if err == nil {
			t.Fatal("a foreign certificate must fail the handshake")
		}
	})
}

func TestEnvelopeCannotClaimAnotherTenant(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	first, firstEnvironment := platform.newTenant(t, "Acme")
	second, _ := platform.newTenant(t, "Globex")
	agent := platform.enroll(t, first.ID, firstEnvironment.ID)

	certificate, err := agent.store.ClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := rawClient(t, platform, certificate)
	request := &agentv1.ReportSourcesRequest{
		Envelope: &agentv1.Envelope{
			SchemaVersion: 1, TenantId: second.ID.String(), AgentId: agent.store.AgentID().String(),
			MessageId: uuid.NewString(),
		},
		Sources: []*agentv1.SourceReport{{SourceKey: "stolen", Engine: agentv1.Engine_ENGINE_MYSQL}},
	}
	_, err = client.ReportSources(ctx, connect.NewRequest(request))
	if connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("err = %v", err)
	}
	sources, err := platform.app.Fleet.ListSources(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(sources) != 0 {
		t.Fatalf("data was written into another tenant: %+v", sources)
	}
}

func TestServerRejectsMessageBreakingTheContract(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	agent := platform.enroll(t, created.ID, environment.ID)
	certificate, err := agent.store.ClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	// A compromised agent skips its own guard; the server must not rely on it.
	request := &agentv1.HeartbeatRequest{
		Envelope: &agentv1.Envelope{
			SchemaVersion: 1, TenantId: created.ID.String(), AgentId: agent.store.AgentID().String(),
			MessageId: "not-a-uuid",
		},
	}
	_, err = rawClient(t, platform, certificate).Heartbeat(ctx, connect.NewRequest(request))
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Fatalf("err = %v", err)
	}
}

func TestTenantsCannotSeeEachOther(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	first, firstEnvironment := platform.newTenant(t, "Acme")
	second, secondEnvironment := platform.newTenant(t, "Globex")
	firstAgent := platform.enroll(t, first.ID, firstEnvironment.ID)
	platform.enroll(t, second.ID, secondEnvironment.ID)

	agents, err := platform.app.Fleet.ListAgents(ctx, second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(agents) != 1 || agents[0].TenantID != second.ID {
		t.Fatalf("listing leaked other tenants: %+v", agents)
	}
	if err := platform.app.Fleet.Revoke(ctx, second.ID, firstAgent.store.AgentID()); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("revoking another tenant's agent: %v", err)
	}
	if _, _, err := platform.app.Fleet.CreateEnrollmentToken(ctx, second.ID, firstEnvironment.ID); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("token for another tenant's environment: %v", err)
	}
}

func TestPolicyDeliveryAndRollbackProtection(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	agent := platform.enroll(t, created.ID, environment.ID)

	for range 2 {
		if _, err := platform.app.Policies.Publish(ctx, created.ID, "tester", nil, &agentv1.ScanBudget{MaxConnections: 2}); err != nil {
			t.Fatalf("Publish: %v", err)
		}
	}
	latest, err := agent.client.GetPolicy(ctx)
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	policy, err := agent.store.AcceptPolicy(latest.GetPolicy(), latest.GetSignature())
	if err != nil {
		t.Fatalf("AcceptPolicy: %v", err)
	}
	if policy.GetVersion() != 2 {
		t.Fatalf("version = %d", policy.GetVersion())
	}

	tampered := append([]byte{}, latest.GetPolicy()...)
	tampered[len(tampered)-1] ^= 0xff
	if _, err := agent.store.AcceptPolicy(tampered, latest.GetSignature()); !errors.Is(err, pki.ErrBadSignature) {
		t.Fatalf("tampered policy: %v", err)
	}

	signer, err := pki.LoadPolicySigner(filepath.Join(platform.pkiDir, pki.PolicyKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	old, err := proto.Marshal(&agentv1.Policy{Version: 1, TenantId: created.ID.String()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.store.AcceptPolicy(old, signer.Sign(old)); !errors.Is(err, identity.ErrPolicyRollback) {
		t.Fatalf("rolled-back policy: %v", err)
	}
	foreign, err := proto.Marshal(&agentv1.Policy{Version: 9, TenantId: uuid.NewString()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.store.AcceptPolicy(foreign, signer.Sign(foreign)); err == nil {
		t.Fatal("a policy of another tenant must be refused")
	}
}

func TestOutboundGuardBlocksBeforeTheWire(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	agent := platform.enroll(t, created.ID, environment.ID)

	_, err := agent.client.ReportSources(ctx, []*agentv1.SourceReport{{
		SourceKey:    "crm",
		Capabilities: []*agentv1.CapabilityStatus{{ReasonCode: "duplicate key canary.subject@dataguard.invalid"}},
	}})
	if !errors.Is(err, egress.ErrBlocked) {
		t.Fatalf("err = %v", err)
	}
}

func restCall(t *testing.T, platform *platform, method, path, token, body string) (int, []byte) {
	t.Helper()
	request, err := http.NewRequest(method, platform.rest.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var payload json.RawMessage
	_ = json.NewDecoder(response.Body).Decode(&payload)
	return response.StatusCode, payload
}

func TestRESTAuthorization(t *testing.T) {
	platform := startPlatform(t)
	first, _ := platform.newTenant(t, "Acme")
	second, _ := platform.newTenant(t, "Globex")
	platform.authn["admin-a"] = api.Principal{Subject: "a", TenantID: first.ID, Roles: []string{api.RoleTenantAdmin}}
	platform.authn["admin-b"] = api.Principal{Subject: "b", TenantID: second.ID, Roles: []string{api.RoleTenantAdmin}}
	platform.authn["auditor-a"] = api.Principal{Subject: "c", TenantID: first.ID, Roles: []string{api.RoleAuditor}}
	platform.authn["platform"] = api.Principal{Subject: "p", Roles: []string{api.RolePlatformAdmin}}
	platform.authn["no-roles"] = api.Principal{Subject: "n", TenantID: first.ID}

	cases := []struct {
		name, method, path, token, body string
		want                            int
	}{
		{"anonymous is refused", http.MethodGet, "/api/v1/environments", "", "", http.StatusUnauthorized},
		{"unknown token is refused", http.MethodGet, "/api/v1/environments", "forged", "", http.StatusUnauthorized},
		{"no roles means no access", http.MethodGet, "/api/v1/environments", "no-roles", "", http.StatusForbidden},
		{"auditor reads", http.MethodGet, "/api/v1/agents", "auditor-a", "", http.StatusOK},
		{"auditor cannot write", http.MethodPost, "/api/v1/environments", "auditor-a", `{"name":"x","kind":"testing"}`, http.StatusForbidden},
		{"tenant admin cannot create tenants", http.MethodPost, "/api/v1/tenants", "admin-a", `{"name":"x"}`, http.StatusForbidden},
		{"platform admin sees no tenant data", http.MethodGet, "/api/v1/agents", "platform", "", http.StatusForbidden},
		{"platform admin lists tenants", http.MethodGet, "/api/v1/tenants", "platform", "", http.StatusOK},
		{"platform admin creates tenants", http.MethodPost, "/api/v1/tenants", "platform", `{"name":"Initech"}`, http.StatusCreated},
		{"duplicate name conflicts", http.MethodPost, "/api/v1/tenants", "platform", `{"name":"Acme"}`, http.StatusConflict},
		{"invalid kind is rejected", http.MethodPost, "/api/v1/environments", "admin-a", `{"name":"x","kind":"bogus"}`, http.StatusBadRequest},
		{"malformed body is rejected", http.MethodPost, "/api/v1/environments", "admin-a", `{`, http.StatusBadRequest},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			status, payload := restCall(t, platform, testCase.method, testCase.path, testCase.token, testCase.body)
			if status != testCase.want {
				t.Fatalf("status = %d, want %d, body %s", status, testCase.want, payload)
			}
		})
	}

	t.Run("environments are tenant scoped", func(t *testing.T) {
		status, payload := restCall(t, platform, http.MethodPost, "/api/v1/environments", "admin-a", `{"name":"only-a","kind":"testing"}`)
		if status != http.StatusCreated {
			t.Fatalf("create: %d %s", status, payload)
		}
		status, payload = restCall(t, platform, http.MethodGet, "/api/v1/environments", "admin-b", "")
		if status != http.StatusOK || strings.Contains(string(payload), "only-a") {
			t.Fatalf("leak: %d %s", status, payload)
		}
	})
}

func TestReadinessReflectsDatabase(t *testing.T) {
	platform := startPlatform(t)
	status, _ := restCall(t, platform, http.MethodGet, "/readyz", "", "")
	if status != http.StatusOK {
		t.Fatalf("readyz = %d", status)
	}
}
