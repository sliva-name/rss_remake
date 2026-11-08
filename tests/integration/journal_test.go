//go:build integration

package integration_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"dataguard/internal/agent/config"
	"dataguard/internal/agent/identity"
	"dataguard/internal/agent/runtime"
	"dataguard/internal/gen/restapi"
	"dataguard/internal/server/api"
)

// Every operator action through the API lands in the journal with who did it,
// in the order it happened, attributed to the organization it belongs to. A
// draft checked and thrown away leaves nothing.
func TestJournalRecordsWhoDidWhat(t *testing.T) {
	platform := startPlatform(t)
	created, _ := platform.newTenant(t, "Acme")
	other, _ := platform.newTenant(t, "Globex")
	platform.authn["admin"] = api.Principal{Subject: "s-ivanova", Name: "ivanova", TenantID: created.ID, Roles: []string{api.RoleTenantAdmin}}
	platform.authn["auditor"] = api.Principal{Subject: "s-petrov", Name: "petrov", TenantID: created.ID, Roles: []string{api.RoleAuditor}}
	platform.authn["analyst"] = api.Principal{Subject: "s-sidorova", Name: "sidorova", TenantID: created.ID, Roles: []string{api.RoleSecurityAnalyst}}
	platform.authn["other"] = api.Principal{Subject: "s-other", Name: "other", TenantID: other.ID, Roles: []string{api.RoleTenantAdmin}}
	must := func(method, path, token, body string, into any) {
		t.Helper()
		status, payload := restCall(t, platform, method, path, token, body)
		if status >= http.StatusMultipleChoices {
			t.Fatalf("%s %s: %d %s", method, path, status, payload)
		}
		if into != nil {
			if err := json.Unmarshal(payload, into); err != nil {
				t.Fatal(err)
			}
		}
	}

	var environment restapi.Environment
	must(http.MethodPost, "/api/v1/environments", "admin", `{"name":"Production","kind":"production"}`, &environment)
	var token restapi.EnrollmentToken
	must(http.MethodPost, "/api/v1/enrollment-tokens", "admin", fmt.Sprintf(`{"environmentId":%q}`, environment.Id), &token)
	dir := t.TempDir()
	settings := &config.Config{StateDir: dir, Center: config.Center{URL: platform.agents.URL, CAFile: platform.caFile}}
	if err := runtime.Enroll(t.Context(), settings, token.Token, "1.0.0"); err != nil {
		t.Fatal(err)
	}
	agent, err := identity.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	sealed := base64.StdEncoding.EncodeToString(sealedFor(t, agent.SealingKey().PublicKey().Bytes()))
	source := func(name string, draft bool) string {
		return fmt.Sprintf(`{"name":%q,"agentId":%q,"engine":"postgresql","host":"db.invalid","port":5432,`+
			`"database":"crm","username":"dg_scanner","tls":"disable","sealedPassword":%q,"draft":%t}`, name, agent.AgentID(), sealed, draft)
	}
	var checked restapi.Source
	must(http.MethodPost, "/api/v1/sources", "admin", source("probe", true), &checked)
	must(http.MethodDelete, "/api/v1/sources/"+checked.Id.String(), "admin", "", nil)
	var crm restapi.Source
	must(http.MethodPost, "/api/v1/sources", "admin", source("crm", false), &crm)
	moved := fmt.Sprintf(`{"name":"crm-main","engine":"postgresql","host":"db.invalid","port":6432,`+
		`"database":"crm","username":"dg_scanner","tls":"disable","sealedPassword":%q}`, sealed)
	must(http.MethodPut, "/api/v1/sources/"+crm.Id.String(), "admin", moved, nil)
	must(http.MethodPut, "/api/v1/policy", "admin", `{"customDetectors":[]}`, nil)
	must(http.MethodPost, "/api/v1/agents/"+agent.AgentID().String()+"/revoke", "admin", "", nil)
	must(http.MethodDelete, "/api/v1/sources/"+crm.Id.String(), "admin", "", nil)

	var journal []restapi.OperatorAction
	must(http.MethodGet, "/api/v1/operator-actions", "auditor", "", &journal)
	var actions []string
	for _, entry := range slices.Backward(journal) {
		actions = append(actions, string(entry.Action))
		// The test set up the organization and its first environment through
		// the services, with nobody behind the request: that is the platform.
		operator := entry.ActorName == "ivanova" && entry.ActorSubject == "s-ivanova"
		platformItself := entry.ActorSubject == "" && len(actions) <= 2
		if !operator && !platformItself {
			t.Errorf("%s is attributed to %q (%q)", entry.Action, entry.ActorName, entry.ActorSubject)
		}
	}
	want := []string{
		"tenant.create", "environment.create",
		"environment.create", "enrollment_token.issue", "agent.enroll", "source.create", "source.update",
		"policy.publish", "agent.revoke", "source.delete",
	}
	if !slices.Equal(actions, want) {
		t.Fatalf("journal, oldest first:\n got %v\nwant %v", actions, want)
	}
	update := journal[slices.IndexFunc(journal, func(entry restapi.OperatorAction) bool { return entry.Action == "source.update" })]
	if update.ObjectId != crm.Id || update.ObjectLabel != "crm-main" || update.Details["changes"] != "name,port,password" {
		t.Fatalf("source update entry = %+v", update)
	}
	if strings.Contains(fmt.Sprint(journal), sealed) || strings.Contains(fmt.Sprint(journal), "6432") {
		t.Fatal("a setting value or the sealed password reached the journal")
	}
	var ofSource []restapi.OperatorAction
	must(http.MethodGet, "/api/v1/operator-actions?objectId="+crm.Id.String(), "admin", "", &ofSource)
	if len(ofSource) != 3 {
		t.Fatalf("journal of the source has %d entries, want create, update and delete", len(ofSource))
	}
	var page []restapi.OperatorAction
	must(http.MethodGet, "/api/v1/operator-actions?limit=2&before="+journal[1].Id.String(), "admin", "", &page)
	if len(page) != 2 || page[0].Id != journal[2].Id {
		t.Fatalf("the page after the second entry starts at %v", page)
	}

	if status, _ := restCall(t, platform, http.MethodGet, "/api/v1/operator-actions", "analyst", ""); status != http.StatusForbidden {
		t.Fatalf("an analyst read the journal: %d", status)
	}
	var foreign []restapi.OperatorAction
	must(http.MethodGet, "/api/v1/operator-actions", "other", "", &foreign)
	for _, entry := range foreign {
		if entry.ActorSubject != "" || (entry.ObjectId != other.ID && entry.Action != "environment.create") {
			t.Fatalf("another organization sees %+v", entry)
		}
	}
}

// The server's database role can add entries but not rewrite or remove them,
// so a compromised server cannot cover its tracks in the journal.
func TestJournalOnlyGrows(t *testing.T) {
	ctx := t.Context()
	platform := startPlatform(t)
	created, _ := platform.newTenant(t, "Acme")
	connection, err := pgx.Connect(ctx, platform.runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close(ctx) }()
	for _, statement := range []string{
		`UPDATE operator_actions SET actor_name = 'someone else'`,
		`DELETE FROM operator_actions`,
		`TRUNCATE operator_actions`,
	} {
		tx, err := connection.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, created.ID.String()); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, statement); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s: err = %v", statement, err)
		}
		_ = tx.Rollback(ctx)
	}
}
