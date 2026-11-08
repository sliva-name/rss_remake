package api

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

type fixedAuthenticator struct {
	principal Principal
}

func (f fixedAuthenticator) Authenticate(context.Context, string) (Principal, error) {
	return f.principal, nil
}

// The handlers reject these before reaching any service, which the empty
// Services here would turn into a panic.
func TestOutOfRangeParametersAreRejected(t *testing.T) {
	handler := Handler(New(Services{}), fixedAuthenticator{Principal{
		Subject: "admin", TenantID: uuid.New(), Roles: []string{RoleTenantAdmin},
	}}, slog.New(slog.DiscardHandler), nil)

	cases := []struct {
		name, method, target, body string
	}{
		{"negative scan limit", http.MethodGet, "/api/v1/scans?limit=-1", ""},
		{"scan limit over maximum", http.MethodGet, "/api/v1/scans?limit=201", ""},
		{"catalog limit over maximum", http.MethodGet, "/api/v1/catalog/columns?limit=501", ""},
		{"negative catalog offset", http.MethodGet, "/api/v1/catalog/columns?offset=-1", ""},
		{"zero change limit", http.MethodGet, "/api/v1/catalog/changes?limit=0", ""},
		{"event limit over maximum", http.MethodGet, "/api/v1/audit/events?limit=100000", ""},
		{"negative event offset", http.MethodGet, "/api/v1/audit/events?offset=-5", ""},
		{"coverage window over maximum", http.MethodGet, "/api/v1/audit/coverage?windowHours=721", ""},
		{"negative budget", http.MethodPut, "/api/v1/policy", `{"customDetectors":[],"scanBudget":{"maxConnections":-1}}`},
		{"budget beyond uint32", http.MethodPut, "/api/v1/policy", `{"customDetectors":[],"scanBudget":{"maxDurationSeconds":4294967296}}`},
		{"zero rows budget", http.MethodPut, "/api/v1/policy", `{"customDetectors":[],"scanBudget":{"maxRowsPerTable":0}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			request.Header.Set("Authorization", "Bearer token")
			if tc.body != "" {
				request.Header.Set("Content-Type", "application/json")
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400; body %s", recorder.Code, recorder.Body.String())
			}
		})
	}
}
