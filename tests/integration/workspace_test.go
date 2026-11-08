//go:build integration

package integration_test

import (
	"net/http"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"

	"dataguard/internal/classifier"
	"dataguard/internal/gen/restapi"
	"dataguard/internal/server/api"
	"dataguard/internal/testkit/seed"
	"dataguard/internal/testkit/stand"
)

// What the dashboard's inventory, search, overview and column pages ask for.
func TestWorkspaceQueries(t *testing.T) {
	source := stand.PostgresSource(t)
	platform, tenantID, sourceID, _ := scanAndAudit(t, source)
	platform.authn["reader"] = api.Principal{Subject: "r", TenantID: tenantID, Roles: []string{api.RoleAuditor}}

	tableNames := func(query string) []string {
		page := restGet[restapi.CatalogTablePage](t, platform, "/api/v1/catalog/tables?sourceId="+sourceID.String()+"&"+query)
		names := make([]string, 0, len(page.Items))
		for _, item := range page.Items {
			names = append(names, item.Table)
		}
		if int(page.Total) != len(names) {
			t.Errorf("?%s: total %d, items %d", query, page.Total, len(names))
		}
		return names
	}
	t.Run("tables by name, sensitivity and category", func(t *testing.T) {
		if names := tableNames("q=DG_US"); !slices.Equal(names, []string{seed.Users}) {
			t.Errorf("q=DG_US: %v", names)
		}
		if names := tableNames("q=%25"); len(names) != 0 {
			t.Errorf("q=%%: a percent sign matched %v", names)
		}
		sensitive := tableNames("sensitive=true")
		if !slices.Contains(sensitive, seed.Users) || slices.Contains(sensitive, seed.Orders) {
			t.Errorf("sensitive: %v", sensitive)
		}
		if names := tableNames("category=" + classifier.CategoryEmail); !slices.Equal(names, []string{seed.Users}) {
			t.Errorf("category: %v", names)
		}
		if names := tableNames("category=NOTHING.STORED"); len(names) != 0 {
			t.Errorf("unknown category: %v", names)
		}
	})

	t.Run("search finds tables and columns", func(t *testing.T) {
		result := restGet[restapi.SearchResult](t, platform, "/api/v1/search?q=dg_us")
		if !slices.ContainsFunc(result.Tables, func(hit restapi.SearchHit) bool { return hit.Name == seed.Users }) {
			t.Errorf("tables: %+v", result.Tables)
		}
		result = restGet[restapi.SearchResult](t, platform, "/api/v1/search?q=emai")
		index := slices.IndexFunc(result.Columns, func(hit restapi.SearchHit) bool { return hit.Name == "email" })
		if index < 0 || result.Columns[index].Categories == nil || !slices.Contains(*result.Columns[index].Categories, classifier.CategoryEmail) {
			t.Errorf("columns: %+v", result.Columns)
		}
		if status, _ := restCall(t, platform, http.MethodGet, "/api/v1/search?q=e", "reader", ""); status != http.StatusBadRequest {
			t.Errorf("one letter: %d", status)
		}
	})

	if _, err := source.Admin.ExecContext(t.Context(), `SELECT email FROM `+seed.Users); err != nil {
		t.Fatal(err)
	}
	table := restGet[restapi.CatalogTablePage](t, platform, "/api/v1/catalog/tables?q="+seed.Users).Items[0]
	detail := restGet[restapi.CatalogTableDetail](t, platform, "/api/v1/catalog/tables/"+table.Id.String())
	email := detail.Columns[slices.IndexFunc(detail.Columns, func(column restapi.TableColumn) bool { return column.Name == "email" })]

	t.Run("who read one column", func(t *testing.T) {
		deadline := time.Now().Add(auditWait)
		for {
			rows := restGet[[]restapi.PrincipalAccess](t, platform, "/api/v1/analytics/principals?columnId="+email.Id.String())
			if slices.ContainsFunc(rows, func(row restapi.PrincipalAccess) bool { return row.DatabasePrincipal == "dg_app" && row.Events > 0 }) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("dg_app never read the column: %+v", rows)
			}
			time.Sleep(200 * time.Millisecond)
		}
		if rows := restGet[[]restapi.PrincipalAccess](t, platform, "/api/v1/analytics/principals?columnId="+uuid.NewString()); len(rows) != 0 {
			t.Errorf("unknown column has readers: %+v", rows)
		}
	})

	t.Run("events per hour", func(t *testing.T) {
		points := restGet[[]restapi.TimelinePoint](t, platform, "/api/v1/analytics/timeline")
		var events, sensitive int64
		for i, point := range points {
			if point.Hour.Minute() != 0 || point.Hour.Second() != 0 || (i > 0 && !points[i-1].Hour.Before(point.Hour)) {
				t.Fatalf("points are not whole ascending hours: %+v", points)
			}
			events += point.Events
			sensitive += point.SensitiveEvents
		}
		if events == 0 || sensitive == 0 || sensitive > events {
			t.Errorf("events %d, sensitive %d", events, sensitive)
		}
		long := url.Values{"from": {time.Now().Add(-100 * 24 * time.Hour).UTC().Format(time.RFC3339)}}
		if status, _ := restCall(t, platform, http.MethodGet, "/api/v1/analytics/timeline?"+long.Encode(), "reader", ""); status != http.StatusBadRequest {
			t.Errorf("100 days: %d", status)
		}
	})

	t.Run("inventory changes in a period", func(t *testing.T) {
		recent := restGet[[]restapi.CatalogChange](t, platform, "/api/v1/catalog/changes")
		if len(recent) == 0 {
			t.Fatal("no changes after a scan")
		}
		later := url.Values{"from": {time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}}
		if changes := restGet[[]restapi.CatalogChange](t, platform, "/api/v1/catalog/changes?"+later.Encode()); len(changes) != 0 {
			t.Errorf("changes from the future: %+v", changes)
		}
	})
}
