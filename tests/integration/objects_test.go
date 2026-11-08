//go:build integration

package integration_test

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"dataguard/internal/classifier"
	"dataguard/internal/gen/restapi"
	"dataguard/internal/server/api"
	"dataguard/internal/testkit/seed"
	"dataguard/internal/testkit/stand"
)

func restGet[T any](t *testing.T, platform *platform, path string) T {
	t.Helper()
	status, payload := restCall(t, platform, http.MethodGet, path, "reader", "")
	if status != http.StatusOK {
		t.Fatalf("GET %s: %d %s", path, status, payload)
	}
	var value T
	if err := json.Unmarshal(payload, &value); err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return value
}

// awaitEventPage polls the events API until want holds for the page.
func awaitEventPage(t *testing.T, platform *platform, query string, want func(restapi.AuditEventPage) bool) restapi.AuditEventPage {
	t.Helper()
	deadline := time.Now().Add(auditWait)
	for {
		page := restGet[restapi.AuditEventPage](t, platform, "/api/v1/audit/events?"+query)
		if want(page) {
			return page
		}
		if time.Now().After(deadline) {
			t.Fatalf("events ?%s never matched: %+v", query, page.Items)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// The chain the dashboard links through: source, agent, table, column,
// classification, events. Event names come from the query and catalog names
// from the scan, so each engine is checked that the two meet.
func TestObjectsLeadFromSourceToEventsOfOneColumn(t *testing.T) {
	for _, source := range stand.AllSources(t) {
		t.Run(source.Dialect.Name, func(t *testing.T) {
			ctx := context.Background()
			// The MySQL general log names the user only at login.
			source.Admin.SetMaxIdleConns(0)
			platform, tenantID, sourceID, _ := scanAndAudit(t, source)
			platform.authn["reader"] = api.Principal{Subject: "r", TenantID: tenantID, Roles: []string{api.RoleAuditor, api.RoleSecurityAnalyst}}

			got := restGet[restapi.Source](t, platform, "/api/v1/sources/"+sourceID.String())
			listed := restGet[[]restapi.Source](t, platform, "/api/v1/sources")
			if len(got.Capabilities) == 0 || len(listed) != 1 || !slices.Equal(got.Capabilities, listed[0].Capabilities) {
				t.Fatalf("one source has capabilities %+v, the list %+v", got.Capabilities, listed)
			}
			agent := restGet[restapi.Agent](t, platform, "/api/v1/agents/"+got.AgentId.String())
			if agent.Id != got.AgentId {
				t.Fatalf("agent = %+v", agent)
			}

			tables := restGet[restapi.CatalogTablePage](t, platform, "/api/v1/catalog/tables?sourceId="+sourceID.String())
			index := slices.IndexFunc(tables.Items, func(table restapi.CatalogTable) bool { return table.Table == seed.Users })
			if index < 0 {
				t.Fatalf("no %s among %+v", seed.Users, tables.Items)
			}
			users := tables.Items[index]
			if users.SensitiveColumns == 0 || !slices.Contains(users.Categories, classifier.CategoryEmail) || users.Columns < users.SensitiveColumns {
				t.Fatalf("users = %+v", users)
			}

			table := restGet[restapi.CatalogTableDetail](t, platform, "/api/v1/catalog/tables/"+users.Id.String())
			column := slices.IndexFunc(table.Columns, func(column restapi.TableColumn) bool { return column.Name == "email" })
			if table.SourceId != sourceID || table.Status != restapi.ObjectStatusActive || column < 0 {
				t.Fatalf("table = %+v", table)
			}
			email := table.Columns[column]
			if !slices.Contains(email.Categories, classifier.CategoryEmail) {
				t.Fatalf("email = %+v", email)
			}

			detail := restGet[restapi.CatalogColumnDetail](t, platform, "/api/v1/catalog/columns/"+email.Id.String())
			if detail.TableId != table.Id || detail.SourceId != sourceID || detail.Name != "email" {
				t.Fatalf("column = %+v", detail)
			}
			if !slices.ContainsFunc(detail.Classifications, func(decision restapi.Classification) bool {
				return decision.CategoryId == classifier.CategoryEmail && decision.Detected && decision.RowsMatched > 0
			}) {
				t.Fatalf("classifications = %+v", detail.Classifications)
			}

			for _, statement := range []string{
				`SELECT email FROM ` + seed.Users,
				`SELECT count(*) FROM ` + seed.Users,
				`SELECT note FROM ` + seed.Orders,
			} {
				if _, err := source.Admin.ExecContext(ctx, statement); err != nil {
					t.Fatalf("%s: %v", statement, err)
				}
			}

			byColumn := awaitEventPage(t, platform, "columnId="+email.Id.String(), func(page restapi.AuditEventPage) bool {
				return len(page.Items) > 0
			})
			for _, event := range byColumn.Items {
				if !slices.ContainsFunc(event.Columns, func(name string) bool { return strings.HasSuffix(name, ".email") }) || event.SourceId != sourceID {
					t.Errorf("column filter let through %+v", event)
				}
			}

			// count(*) reads no column: only the table name ties it to the table.
			byTable := awaitEventPage(t, platform, "tableId="+table.Id.String(), func(page restapi.AuditEventPage) bool {
				return slices.ContainsFunc(page.Items, func(event restapi.AuditEvent) bool { return len(event.Columns) == 0 })
			})
			for _, event := range byTable.Items {
				if slices.ContainsFunc(event.Tables, func(name string) bool { return strings.HasSuffix(name, seed.Orders) }) &&
					!slices.ContainsFunc(event.Tables, func(name string) bool { return strings.HasSuffix(name, seed.Users) }) {
					t.Errorf("table filter let through %+v", event)
				}
			}

			other := restGet[restapi.AuditEventPage](t, platform, "/api/v1/audit/events?tableId="+table.Id.String()+"&sourceId="+uuid.NewString())
			if len(other.Items) != 0 {
				t.Errorf("table of another source matched %d events", len(other.Items))
			}
		})
	}
}

func TestObjectsOfAnotherTenantAreNotFound(t *testing.T) {
	source := stand.PostgresSource(t)
	platform, tenantID, sourceID, _ := scanAndAudit(t, source)
	other, _ := platform.newTenant(t, "Globex")
	platform.authn["reader"] = api.Principal{Subject: "r", TenantID: tenantID, Roles: []string{api.RoleAuditor}}
	platform.authn["outsider"] = api.Principal{Subject: "o", TenantID: other.ID, Roles: []string{api.RoleTenantAdmin}}

	got := restGet[restapi.Source](t, platform, "/api/v1/sources/"+sourceID.String())
	tables := restGet[restapi.CatalogTablePage](t, platform, "/api/v1/catalog/tables?sourceId="+sourceID.String())
	if len(tables.Items) == 0 {
		t.Fatal("no tables")
	}
	table := restGet[restapi.CatalogTableDetail](t, platform, "/api/v1/catalog/tables/"+tables.Items[0].Id.String())
	if len(table.Columns) == 0 {
		t.Fatal("no columns")
	}
	paths := []string{
		"/api/v1/sources/" + sourceID.String(),
		"/api/v1/agents/" + got.AgentId.String(),
		"/api/v1/catalog/tables/" + table.Id.String(),
		"/api/v1/catalog/columns/" + table.Columns[0].Id.String(),
		"/api/v1/audit/events?tableId=" + table.Id.String(),
	}
	for _, path := range paths {
		if status, payload := restCall(t, platform, http.MethodGet, path, "outsider", ""); status != http.StatusNotFound {
			t.Errorf("outsider GET %s: %d %s", path, status, payload)
		}
	}
	if status, _ := restCall(t, platform, http.MethodGet, "/api/v1/catalog/columns/"+uuid.NewString(), "reader", ""); status != http.StatusNotFound {
		t.Errorf("unknown column: %d", status)
	}
	page := restGet[restapi.CatalogTablePage](t, platform, "/api/v1/catalog/tables?sourceId="+uuid.NewString())
	if page.Total != 0 {
		t.Errorf("unknown source lists %d tables", page.Total)
	}
}
