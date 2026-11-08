//go:build integration

package integration_test

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"dataguard/internal/classifier"
	"dataguard/internal/core/scan"
	"dataguard/internal/gen/restapi"
	"dataguard/internal/server/api"
	"dataguard/internal/testkit/seed"
	"dataguard/internal/testkit/stand"
)

// rawCall returns the status, headers and body of a response that is not JSON.
func rawCall(t *testing.T, platform *platform, path, token string) (int, http.Header, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, platform.rest.URL+path, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, response.Header, body
}

func TestPreferencesBelongToOneAccount(t *testing.T) {
	platform := startPlatform(t)
	tenant, _ := platform.newTenant(t, "Acme")
	other, _ := platform.newTenant(t, "Globex")
	platform.authn["ann"] = api.Principal{Subject: "ann", TenantID: tenant.ID, Roles: []string{api.RoleAuditor}}
	platform.authn["bob"] = api.Principal{Subject: "bob", TenantID: tenant.ID, Roles: []string{api.RoleTenantAdmin}}
	platform.authn["ann-elsewhere"] = api.Principal{Subject: "ann", TenantID: other.ID, Roles: []string{api.RoleAuditor}}
	platform.authn["platform"] = api.Principal{Subject: "p", Roles: []string{api.RolePlatformAdmin}}

	views := `{"value":[{"name":"Паспорта за неделю","path":"/audit","query":"category=GOVERNMENT.PASSPORT"}]}`
	if status, payload := restCall(t, platform, http.MethodPut, "/api/v1/preferences/views", "ann", views); status != http.StatusNoContent {
		t.Fatalf("save: %d %s", status, payload)
	}
	read := func(token string) string {
		t.Helper()
		status, payload := restCall(t, platform, http.MethodGet, "/api/v1/preferences/views", token, "")
		if status != http.StatusOK {
			t.Fatalf("%s read: %d %s", token, status, payload)
		}
		var preference restapi.Preference
		if err := json.Unmarshal(payload, &preference); err != nil {
			t.Fatal(err)
		}
		encoded, _ := json.Marshal(preference.Value)
		return string(encoded)
	}
	if got := read("ann"); !strings.Contains(got, "Паспорта за неделю") {
		t.Errorf("ann reads %s", got)
	}
	for _, token := range []string{"bob", "ann-elsewhere"} {
		if got := read(token); got != "null" {
			t.Errorf("%s reads ann's views: %s", token, got)
		}
	}
	if status, _ := restCall(t, platform, http.MethodGet, "/api/v1/preferences/views", "platform", ""); status != http.StatusForbidden {
		t.Errorf("platform admin without an organization: %d", status)
	}
	if status, _ := restCall(t, platform, http.MethodGet, "/api/v1/preferences/passwords", "ann", ""); status != http.StatusBadRequest {
		t.Errorf("unknown key: %d", status)
	}
	huge := fmt.Sprintf(`{"value":"%s"}`, strings.Repeat("x", 70<<10))
	if status, _ := restCall(t, platform, http.MethodPut, "/api/v1/preferences/recent", "ann", huge); status != http.StatusBadRequest {
		t.Errorf("70 KiB value: %d", status)
	}
}

func TestPolicyHistoryKeepsEveryVersion(t *testing.T) {
	platform := startPlatform(t)
	tenant, _ := platform.newTenant(t, "Acme")
	platform.authn["admin"] = api.Principal{Subject: "admin", TenantID: tenant.ID, Roles: []string{api.RoleTenantAdmin}}
	for _, body := range []string{
		`{"customDetectors":[{"categoryId":"CUSTOM.CONTRACT","namePattern":"contract"}]}`,
		`{"customDetectors":[],"scanBudget":{"maxRowsPerTable":500}}`,
	} {
		if status, payload := restCall(t, platform, http.MethodPut, "/api/v1/policy", "admin", body); status != http.StatusCreated {
			t.Fatalf("publish: %d %s", status, payload)
		}
	}
	platform.authn["reader"] = platform.authn["admin"]
	versions := restGet[[]restapi.PolicyVersion](t, platform, "/api/v1/policy/versions")
	if len(versions) != 2 || versions[0].Version != 2 || versions[1].Version != 1 || versions[0].CreatedBy != "admin" {
		t.Fatalf("versions = %+v", versions)
	}
	if versions[1].CustomDetectors != 1 || versions[1].HasScanBudget || !versions[0].HasScanBudget {
		t.Errorf("summaries = %+v", versions)
	}
	first := restGet[restapi.Policy](t, platform, "/api/v1/policy/versions/1")
	if first.Version != 1 || len(first.CustomDetectors) != 1 || first.CustomDetectors[0].CategoryId != "CUSTOM.CONTRACT" {
		t.Errorf("version 1 = %+v", first)
	}
	if status, _ := restCall(t, platform, http.MethodGet, "/api/v1/policy/versions/9", "admin", ""); status != http.StatusNotFound {
		t.Errorf("missing version: %d", status)
	}
}

// What an investigation needs from collected events: session and client
// fields, the session filter, CSV, signals, principals in search, and reports
// without the platform's own scanner reads.
func TestInvestigationOnCollectedEvents(t *testing.T) {
	source := stand.PostgresSource(t)
	source.Admin.SetMaxIdleConns(0)
	platform, tenantID, sourceID, _ := scanAndAudit(t, source)
	platform.authn["reader"] = api.Principal{Subject: "r", TenantID: tenantID, Roles: []string{api.RoleAuditor}}

	if _, err := source.Admin.ExecContext(t.Context(), `SELECT email, inn FROM `+seed.Users); err != nil {
		t.Fatal(err)
	}
	page := awaitEventPage(t, platform, "principal=dg_app&category="+classifier.CategoryEmail, func(page restapi.AuditEventPage) bool { return len(page.Items) > 0 })
	event := page.Items[0]
	if event.SessionId == "" || event.ClientAddress == "" {
		t.Fatalf("session and client are missing: %+v", event)
	}
	session := restGet[restapi.AuditEventPage](t, platform, "/api/v1/audit/events?sessionId="+event.SessionId)
	for _, item := range session.Items {
		if item.SessionId != event.SessionId {
			t.Errorf("session filter let through %+v", item)
		}
	}

	t.Run("reports leave out the scanner", func(t *testing.T) {
		// The collector reads from where it found the log, after the first
		// scan, so a second scan is what leaves scanner reads to leave out.
		job, err := platform.app.Scans.Request(t.Context(), tenantID, sourceID, "tester")
		if err != nil {
			t.Fatal(err)
		}
		if finished := waitForScan(t, platform, tenantID, job.ID); finished.Status != scan.StatusCompleted {
			t.Fatalf("scan: %+v", finished)
		}
		scanner := source.Config.Username
		awaitEventPage(t, platform, "includeScanner=true&principal="+scanner, func(page restapi.AuditEventPage) bool { return len(page.Items) > 0 })
		for _, row := range restGet[[]restapi.PrincipalAccess](t, platform, "/api/v1/analytics/principals") {
			if row.DatabasePrincipal == scanner {
				t.Errorf("scanner in the principals report: %+v", row)
			}
		}
	})

	t.Run("CSV export", func(t *testing.T) {
		status, header, body := rawCall(t, platform, "/api/v1/audit/events/export?principal=dg_app", "reader")
		if status != http.StatusOK {
			t.Fatalf("export: %d %s", status, body)
		}
		if !strings.HasPrefix(header.Get("Content-Type"), "text/csv") || header.Get("X-Dataguard-Truncated") != "false" {
			t.Errorf("headers: %v", header)
		}
		if !bytes.HasPrefix(body, []byte{0xEF, 0xBB, 0xBF}) {
			t.Error("no byte order mark")
		}
		records, err := csv.NewReader(bytes.NewReader(body[3:])).ReadAll()
		if err != nil || len(records) < 2 || records[0][0] != "Время (UTC)" {
			t.Fatalf("csv: %v, %d records", err, len(records))
		}
		if !slices.ContainsFunc(records[1:], func(record []string) bool { return record[3] == "dg_app" }) {
			t.Errorf("no dg_app rows: %v", records[1])
		}
	})

	t.Run("signals for categories read for the first time", func(t *testing.T) {
		signals := restGet[[]restapi.RiskSignal](t, platform, "/api/v1/analytics/signals")
		if !slices.ContainsFunc(signals, func(signal restapi.RiskSignal) bool {
			return signal.Kind == restapi.NEWCATEGORY && signal.DatabasePrincipal == "dg_app" && signal.Category == classifier.CategoryEmail
		}) {
			t.Errorf("a fresh organization reads email for the first time: %+v", signals)
		}
		for _, signal := range signals {
			if signal.DatabasePrincipal == source.Config.Username {
				t.Errorf("signal about the scanner: %+v", signal)
			}
			if time.Since(signal.LastSeen) > 25*time.Hour {
				t.Errorf("signal outside the last day: %+v", signal)
			}
		}
	})

	t.Run("search finds principals but not the scanner", func(t *testing.T) {
		found := restGet[restapi.SearchResult](t, platform, "/api/v1/search?q=dg_ap")
		if !slices.ContainsFunc(found.Principals, func(hit restapi.PrincipalHit) bool { return hit.DatabasePrincipal == "dg_app" && hit.Events > 0 }) {
			t.Errorf("principals: %+v", found.Principals)
		}
		if scanner := restGet[restapi.SearchResult](t, platform, "/api/v1/search?q=dg_scan"); len(scanner.Principals) != 0 {
			t.Errorf("the scanner is searchable: %+v", scanner.Principals)
		}
	})
}
