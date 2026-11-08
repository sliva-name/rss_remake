//go:build integration

package integration_test

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/google/uuid"

	"dataguard/internal/agent/config"
	"dataguard/internal/agent/runtime"
	"dataguard/internal/contract/codes"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/gen/dataguard/agent/v1/agentv1connect"
	"dataguard/internal/gen/restapi"
	"dataguard/internal/platform/pki"
	"dataguard/internal/platform/sealing"
	"dataguard/internal/server/agentapi"
	"dataguard/internal/server/api"
)

// An agent newer than the center, or one the center no longer supports, is
// refused with a code the dashboard explains, and is accepted again once it
// speaks a supported contract.
func TestCenterRefusesAContractItDoesNotSpeak(t *testing.T) {
	ctx := t.Context()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	agent := platform.enroll(t, created.ID, environment.ID)
	agentID := agent.store.AgentID()
	certificate, err := agent.store.ClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	platform.authn["admin"] = api.Principal{Subject: "admin", TenantID: created.ID, Roles: []string{api.RoleTenantAdmin}}
	problem := func() string {
		t.Helper()
		status, body := restCall(t, platform, http.MethodGet, "/api/v1/agents/"+agentID.String(), "admin", "")
		var shown restapi.Agent
		if status != http.StatusOK || json.Unmarshal(body, &shown) != nil {
			t.Fatalf("get agent: %d %s", status, body)
		}
		if shown.ProblemCode == nil {
			return ""
		}
		return *shown.ProblemCode
	}

	for _, offered := range []uint32{agentapi.CurrentSchemaVersion + 1, agentapi.MinSchemaVersion - 1} {
		_, err = rawClient(t, platform, certificate).Heartbeat(ctx, &agentv1.HeartbeatRequest{
			Envelope: &agentv1.Envelope{
				SchemaVersion: offered, TenantId: created.ID.String(), AgentId: agentID.String(), MessageId: uuid.NewString(),
			},
			AgentVersion: "9.0.0",
		})
		if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), codes.ContractUnsupported) {
			t.Fatalf("contract %d: err = %v", offered, err)
		}
		refused, err := platform.app.Fleet.GetAgent(ctx, created.ID, agentID)
		if err != nil {
			t.Fatal(err)
		}
		if refused.RefusedContractVersion == nil || *refused.RefusedContractVersion != offered {
			t.Fatalf("contract %d: refusal not recorded: %v", offered, refused.RefusedContractVersion)
		}
		if refused.Version == "9.0.0" {
			t.Fatal("a refused heartbeat changed the recorded agent version")
		}
		if got := problem(); got != codes.ContractUnsupported {
			t.Fatalf("contract %d: dashboard problem = %q", offered, got)
		}
	}

	if _, err := agent.client.Heartbeat(ctx, &agentv1.HeartbeatRequest{AgentVersion: "1.0.0"}); err != nil {
		t.Fatalf("supported heartbeat: %v", err)
	}
	accepted, err := platform.app.Fleet.GetAgent(ctx, created.ID, agentID)
	if err != nil {
		t.Fatal(err)
	}
	if accepted.RefusedContractVersion != nil || accepted.ContractVersion != agentapi.CurrentSchemaVersion {
		t.Fatalf("after an accepted heartbeat: contract %d, refused %v", accepted.ContractVersion, accepted.RefusedContractVersion)
	}
	if got := problem(); got != "" {
		t.Fatalf("problem stayed after the agent was accepted: %q", got)
	}
}

// Enrollment checks the contract before it spends the one-time token, so an
// operator who installed the wrong agent version can reuse the token.
func TestEnrollmentWithAnUnsupportedContractKeepsTheToken(t *testing.T) {
	ctx := t.Context()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	token, _, err := platform.app.Fleet.CreateEnrollmentToken(ctx, created.ID, environment.ID)
	if err != nil {
		t.Fatal(err)
	}
	csr, _, err := pki.NewCSR()
	if err != nil {
		t.Fatal(err)
	}
	key, err := sealing.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	_, err = rawEnrollmentClient(t, platform).Enroll(ctx, &agentv1.EnrollRequest{
		EnrollmentToken: token, CsrPem: csr, AgentVersion: "9.0.0", SealingPublicKey: key.PublicKey().Bytes(),
		SchemaVersion: agentapi.CurrentSchemaVersion + 1,
	})
	if connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), codes.ContractUnsupported) {
		t.Fatalf("err = %v", err)
	}
	settings := &config.Config{StateDir: t.TempDir(), Center: config.Center{URL: platform.agents.URL, CAFile: platform.caFile}}
	if err := runtime.Enroll(ctx, settings, token, "1.0.0"); err != nil {
		t.Fatalf("the token did not survive the refused enrollment: %v", err)
	}
}

func rawEnrollmentClient(t *testing.T, platform *platform) agentv1connect.EnrollmentServiceClient {
	t.Helper()
	caPEM, err := os.ReadFile(platform.caFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}, ForceAttemptHTTP2: true}
	return agentv1connect.NewEnrollmentServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{Transport: transport}, platform.agents.URL)))
}
