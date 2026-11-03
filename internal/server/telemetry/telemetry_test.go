package telemetry_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"dataguard/internal/server/telemetry"
)

// A path carries identifiers; the label must be the template the router matched.
func TestRequestsAreCountedByRouteTemplate(t *testing.T) {
	metrics := telemetry.New()
	router := http.NewServeMux()
	router.HandleFunc("GET /api/v1/sources/{id}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) })
	handler := metrics.API(router, router)
	for _, target := range []string{"/api/v1/sources/0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e1f", "/api/v1/unknown/crm.public.users"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, target, nil))
	}
	samples, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if samples["dataguard_server_api_requests_total|route=GET /api/v1/sources/{id}|status=404"] != 1 {
		t.Fatalf("samples = %v", samples)
	}
	for key := range samples {
		if strings.Contains(key, "0190a8c4") || strings.Contains(key, "crm.public") {
			t.Fatalf("a path value reached a label: %s", key)
		}
	}
}

func TestIngestCountsDuplicatesAndDelay(t *testing.T) {
	metrics := telemetry.New()
	metrics.Ingested(2, 3, []time.Duration{time.Second, 2 * time.Minute})
	samples, err := metrics.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if samples["dataguard_server_events_ingested_total|result=stored"] != 2 ||
		samples["dataguard_server_events_ingested_total|result=duplicate"] != 3 ||
		samples["dataguard_server_event_delivery_delay_seconds"] != 2 {
		t.Fatalf("samples = %v", samples)
	}
}
