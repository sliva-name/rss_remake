//go:build integration

package integration_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"dataguard/internal/agent/identity"
	"dataguard/internal/core/fleet"
	"dataguard/internal/core/scan"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/gen/restapi"
	"dataguard/internal/platform/pki"
	"dataguard/internal/platform/sealing"
	"dataguard/internal/server/api"
	"dataguard/internal/testkit/stand"
)

func TestSourceListIsSignedAddressedAndOnlyGrows(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	agent := platform.enroll(t, created.ID, environment.ID)
	neighbour := platform.enroll(t, created.ID, environment.ID)
	sourceID := platform.addSource(t, agent, placeholderSource())

	beat, err := agent.client.Heartbeat(ctx, &agentv1.HeartbeatRequest{})
	if err != nil || beat.GetLatestSourcesVersion() == 0 {
		t.Fatalf("heartbeat does not announce the list: %v %v", beat, err)
	}
	response, err := agent.client.GetSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	list, err := agent.store.AcceptSources(response.GetSourceList(), response.GetSignature())
	if err != nil {
		t.Fatalf("AcceptSources: %v", err)
	}
	if len(list.GetSources()) != 1 || list.GetSources()[0].GetSourceId() != sourceID.String() {
		t.Fatalf("list = %+v", list)
	}
	definition := list.GetSources()[0]
	password, err := sealing.Open(agent.store.SealingKey(), sealing.Binding{
		TenantID: created.ID, AgentID: agent.store.AgentID(), Engine: "postgresql", Host: definition.GetHost(),
		Port: int(definition.GetPort()), Database: definition.GetDatabase(), Username: definition.GetUsername(), TLS: "disable",
	}, definition.GetSealedPassword())
	if err != nil || string(password) != placeholderSource().Password {
		t.Fatalf("the agent cannot open its password: %v", err)
	}

	t.Run("another agent of the tenant gets nothing", func(t *testing.T) {
		other, err := neighbour.client.GetSources(ctx)
		if err != nil {
			t.Fatal(err)
		}
		accepted, err := neighbour.store.AcceptSources(other.GetSourceList(), other.GetSignature())
		if err != nil || len(accepted.GetSources()) != 0 {
			t.Fatalf("neighbour list = %+v, %v", accepted, err)
		}
		if _, err := neighbour.store.AcceptSources(response.GetSourceList(), response.GetSignature()); err == nil {
			t.Fatal("a list addressed to another agent was accepted")
		}
	})

	t.Run("a policy signature does not pass for a source list", func(t *testing.T) {
		signer, err := pki.LoadPolicySigner(filepath.Join(platform.pkiDir, pki.PolicyKeyFile))
		if err != nil {
			t.Fatal(err)
		}
		forged, err := proto.Marshal(&agentv1.SourceList{Version: 99, TenantId: created.ID.String(), AgentId: agent.store.AgentID().String()})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := agent.store.AcceptSources(forged, signer.Sign(forged)); !errors.Is(err, pki.ErrBadSignature) {
			t.Fatalf("err = %v", err)
		}
	})

	t.Run("an older list is refused", func(t *testing.T) {
		if err := platform.app.Fleet.DeleteSource(ctx, created.ID, sourceID); err != nil {
			t.Fatal(err)
		}
		newer, err := agent.client.GetSources(ctx)
		if err != nil {
			t.Fatal(err)
		}
		emptied, err := agent.store.AcceptSources(newer.GetSourceList(), newer.GetSignature())
		if err != nil || len(emptied.GetSources()) != 0 || emptied.GetVersion() <= list.GetVersion() {
			t.Fatalf("after delete: %+v %v", emptied, err)
		}
		if _, err := agent.store.AcceptSources(response.GetSourceList(), response.GetSignature()); !errors.Is(err, identity.ErrSourcesRollback) {
			t.Fatalf("replayed list: %v", err)
		}
	})
}

// TestAgentRefusesWhatTheCenterShouldNotAsk plays a compromised center: it
// points the agent outside its allowlist, and moves a sealed password to
// another allowed target behind the API's back.
func TestAgentRefusesWhatTheCenterShouldNotAsk(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	enrolled := platform.enroll(t, created.ID, environment.ID)

	outside := placeholderSource()
	outside.Name, outside.Host = "outside", "10.255.0.1"
	foreignLogs := placeholderSource()
	foreignLogs.Name, foreignLogs.Host, foreignLogs.AuditDirectory = "foreign-logs", "127.0.0.1", "/var/lib/dataguard"
	moved := stand.PostgresSource(t).Config
	moved.Name = "moved"
	agent, ids := platform.startAgent(t, enrolled, outside, foreignLogs, moved)

	if source := waitForProbe(t, platform, created.ID, ids[0]); source.StatusCode != "TARGET_NOT_ALLOWED" {
		t.Errorf("outside the allowlist: %q", source.StatusCode)
	}
	if source := waitForProbe(t, platform, created.ID, ids[1]); source.StatusCode != "AUDIT_DIRECTORY_NOT_ALLOWED" {
		t.Errorf("audit directory outside the allowlist: %q", source.StatusCode)
	}
	if source := waitForProbe(t, platform, created.ID, ids[2]); source.StatusCode != "" || source.EngineVersion == "" {
		t.Fatalf("the legitimate source did not open: %+v; logs: %s", source, agent.logs.String())
	}

	// SQL Server is also on loopback, so the allowlist alone would let this through.
	connection, err := pgx.Connect(ctx, platform.ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close(ctx) }()
	if _, err := connection.Exec(ctx, `UPDATE sources SET port = $2, probed_at = NULL WHERE id = $1`, ids[2], stand.MSSQLPort); err != nil {
		t.Fatal(err)
	}
	if _, err := connection.Exec(ctx, `UPDATE agents SET sources_version = sources_version + 1 WHERE id = $1`, enrolled.store.AgentID()); err != nil {
		t.Fatal(err)
	}
	if source := waitForProbe(t, platform, created.ID, ids[2]); source.StatusCode != "CREDENTIAL_UNREADABLE" {
		t.Fatalf("a password moved to another target: %q", source.StatusCode)
	}
}

func TestSourcesAreTenantScoped(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	first, firstEnvironment := platform.newTenant(t, "Acme")
	second, _ := platform.newTenant(t, "Globex")
	agent := platform.enroll(t, first.ID, firstEnvironment.ID)
	sourceID := platform.addSource(t, agent, placeholderSource())

	if _, err := platform.app.Fleet.UpdateSource(ctx, second.ID, sourceID, fleet.Source{
		Key: "taken", Engine: "postgresql", Host: "db.invalid", Port: 5432, Database: "crm", Username: "x", TLS: "disable",
	}); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("update from another tenant: %v", err)
	}
	if err := platform.app.Fleet.DeleteSource(ctx, second.ID, sourceID); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("delete from another tenant: %v", err)
	}
	stolen := fleet.Source{
		Key: "stolen", AgentID: agent.store.AgentID(), Engine: "postgresql", Host: "db.invalid", Port: 5432,
		Database: "crm", Username: "x", TLS: "disable", SealedPassword: sealedFor(t, agent.store.SealingKey().PublicKey().Bytes()),
	}
	if _, err := platform.app.Fleet.CreateSource(ctx, second.ID, stolen); !errors.Is(err, fleet.ErrNotFound) {
		t.Fatalf("a source on another tenant's agent: %v", err)
	}
	listed, err := platform.app.Fleet.ListSources(ctx, second.ID)
	if err != nil || len(listed) != 0 {
		t.Fatalf("leak: %+v %v", listed, err)
	}
}

func TestDeletedSourceIsNoLongerServed(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	agent := platform.enroll(t, created.ID, environment.ID)
	sourceID := platform.addSource(t, agent, placeholderSource())
	pending, err := platform.app.Scans.Request(ctx, created.ID, sourceID, "tester")
	if err != nil {
		t.Fatal(err)
	}
	if err := platform.app.Fleet.DeleteSource(ctx, created.ID, sourceID); err != nil {
		t.Fatal(err)
	}
	if _, err := platform.app.Scans.Request(ctx, created.ID, sourceID, "tester"); !errors.Is(err, scan.ErrNotFound) {
		t.Fatalf("scan of a deleted source: %v", err)
	}
	jobs, err := platform.app.Scans.List(ctx, created.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, job := range jobs {
		if job.ID == pending.ID && job.Status != scan.StatusCancelled {
			t.Fatalf("a queued scan of a deleted source is %s", job.Status)
		}
	}
	if leased, err := agent.client.PullJobs(ctx, 4); err != nil || len(leased) != 0 {
		t.Fatalf("leased jobs of a deleted source: %v %v", leased, err)
	}
	// The name is free again, as the history stays with the old id.
	if again := platform.addSource(t, agent, placeholderSource()); again == sourceID {
		t.Fatal("a new source reused the old id")
	}
}

func sealedFor(t *testing.T, agentPublic []byte) []byte {
	t.Helper()
	sealed, err := sealing.Seal(agentPublic, sealing.Binding{
		TenantID: uuid.New(), AgentID: uuid.New(), Engine: "postgresql", Host: "db.invalid", Port: 5432,
		Database: "crm", Username: "x", TLS: "disable",
	}, []byte("synthetic-password"))
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func TestSourceManagementOverREST(t *testing.T) {
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	agent := platform.enroll(t, created.ID, environment.ID)
	platform.authn["admin"] = api.Principal{Subject: "a", TenantID: created.ID, Roles: []string{api.RoleTenantAdmin}}
	platform.authn["analyst"] = api.Principal{Subject: "s", TenantID: created.ID, Roles: []string{api.RoleSecurityAnalyst}}

	sealed := base64.StdEncoding.EncodeToString(sealedFor(t, agent.store.SealingKey().PublicKey().Bytes()))
	body := fmt.Sprintf(`{"name":"crm","agentId":%q,"engine":"postgresql","host":"db.invalid","port":5432,`+
		`"database":"crm","username":"dg_scanner","tls":"disable","sealedPassword":%q}`, agent.store.AgentID(), sealed)
	if status, _ := restCall(t, platform, http.MethodPost, "/api/v1/sources", "analyst", body); status != http.StatusForbidden {
		t.Fatalf("analyst created a source: %d", status)
	}
	status, payload := restCall(t, platform, http.MethodPost, "/api/v1/sources", "admin", body)
	if status != http.StatusCreated {
		t.Fatalf("create: %d %s", status, payload)
	}
	if status, _ := restCall(t, platform, http.MethodPost, "/api/v1/sources", "admin", body); status != http.StatusConflict {
		t.Fatalf("duplicate name: %d", status)
	}
	plaintext := fmt.Sprintf(`{"name":"plain","agentId":%q,"engine":"postgresql","host":"db.invalid","port":5432,`+
		`"database":"crm","username":"dg_scanner","tls":"disable","sealedPassword":%q}`,
		agent.store.AgentID(), base64.StdEncoding.EncodeToString([]byte("plaintext-password")))
	if status, _ := restCall(t, platform, http.MethodPost, "/api/v1/sources", "admin", plaintext); status != http.StatusBadRequest {
		t.Fatalf("an unsealed password was accepted: %d", status)
	}
	status, agents := restCall(t, platform, http.MethodGet, "/api/v1/agents", "analyst", "")
	want := base64.StdEncoding.EncodeToString(agent.store.SealingKey().PublicKey().Bytes())
	if status != http.StatusOK || !strings.Contains(string(agents), want) {
		t.Fatalf("agents do not publish the sealing key: %d %s", status, agents)
	}
	status, listed := restCall(t, platform, http.MethodGet, "/api/v1/sources", "analyst", "")
	if status != http.StatusOK || strings.Contains(string(listed), sealed) {
		t.Fatalf("the sealed password is listed back: %d", status)
	}
}

func TestScannerReadsAreHiddenUnlessAsked(t *testing.T) {
	ctx := context.Background()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	agent := platform.enroll(t, created.ID, environment.ID)
	sourceID := platform.addSource(t, agent, placeholderSource())
	platform.authn["analyst"] = api.Principal{Subject: "s", TenantID: created.ID, Roles: []string{api.RoleSecurityAnalyst}}

	var events []*agentv1.AuditEvent
	for _, principal := range []string{placeholderSource().Username, "crm_service"} {
		events = append(events, &agentv1.AuditEvent{
			EventId: uuid.NewString(), SourceId: sourceID.String(), EventTime: timestamppb.Now(),
			EventType: agentv1.EventType_EVENT_TYPE_DATA_ACCESS, Actor: &agentv1.Actor{DatabasePrincipal: principal},
		})
	}
	accepted, err := agent.client.SubmitEvents(ctx, events)
	if err != nil || len(accepted) != len(events) {
		t.Fatalf("accepted %v: %v", accepted, err)
	}
	platform.awaitStored(t, created.ID, len(events))
	totals := map[string]int{}
	for _, query := range []string{"", "?includeScanner=true"} {
		status, payload := restCall(t, platform, http.MethodGet, "/api/v1/audit/events"+query, "analyst", "")
		var page restapi.AuditEventPage
		if status != http.StatusOK || json.Unmarshal(payload, &page) != nil {
			t.Fatalf("%q: %d %s", query, status, payload)
		}
		totals[query] = int(page.Total)
	}
	if totals[""] != 1 || totals["?includeScanner=true"] != 2 {
		t.Fatalf("totals = %v", totals)
	}
}
