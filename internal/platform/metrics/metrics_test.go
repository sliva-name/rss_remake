package metrics_test

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"dataguard/internal/platform/metrics"
)

func TestLabelValueOutsideItsKindNeverReachesTheEndpoint(t *testing.T) {
	registry := metrics.New("test")
	counter := registry.Counter("events_total", "Events.", metrics.Code("reason"), metrics.UUID("source_id"))
	counter.Inc("LOG_ROTATED", "0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e1f")
	counter.Inc("dgcanary.value@example.invalid", "crm.public.users")
	counter.Inc("ONLY_ONE_VALUE")

	recorder := httptest.NewRecorder()
	registry.Handler().ServeHTTP(recorder, httptest.NewRequest("GET", "/metrics", nil))
	body, err := io.ReadAll(recorder.Result().Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"dgcanary", "example.invalid", "crm.public"} {
		if strings.Contains(string(body), leaked) {
			t.Fatalf("%q reached the endpoint", leaked)
		}
	}
	samples, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if samples["test_events_total|reason=LOG_ROTATED|source_id=0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e1f"] != 1 {
		t.Fatalf("valid sample missing: %v", samples)
	}
	if samples["test_events_total|reason=INVALID|source_id=INVALID"] != 2 {
		t.Fatalf("invalid values must fold into INVALID: %v", samples)
	}
	if samples["test_metric_label_rejections_total|metric=test_events_total"] != 2 {
		t.Fatalf("rejections must be counted: %v", samples)
	}
}

func TestEnumAndRouteAcceptOnlyTheirValues(t *testing.T) {
	registry := metrics.New("test")
	gauge := registry.Gauge("state", "State.", metrics.Enum("state", "OBSERVING", "DEGRADED"), metrics.Route("route"))
	gauge.Set(1, "OBSERVING", "GET /api/v1/sources/{id}")
	gauge.Set(1, "observing", "GET /api/v1/sources/0190a8c4?name=crm users")
	samples, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if samples["test_state|route=GET /api/v1/sources/{id}|state=OBSERVING"] != 1 || samples["test_state|route=INVALID|state=INVALID"] != 1 {
		t.Fatalf("samples = %v", samples)
	}
}

func TestSnapshotForgetsWhatTheProcessNoLongerHas(t *testing.T) {
	registry := metrics.New("test")
	sources := []string{"0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e1f", "0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e20"}
	registry.Snapshot("sources", "Sources.", func(emit metrics.Emit) {
		for _, id := range sources {
			emit(1, id)
		}
	}, metrics.UUID("source_id"))
	sources = sources[:1]
	samples, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(samplesNamed(samples, "test_sources")) != 1 {
		t.Fatalf("samples = %v", samples)
	}
}

func samplesNamed(samples map[string]float64, name string) []string {
	var keys []string
	for key := range samples {
		if strings.HasPrefix(key, name+"|") {
			keys = append(keys, key)
		}
	}
	return keys
}
