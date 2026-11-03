// Package telemetry holds the server's metrics (ADR-0008). They carry no tenant,
// agent or source: the endpoint is read by operators of the platform, who must
// not learn about one tenant through it, and the runtime database role cannot
// read across tenants anyway.
package telemetry

import (
	"context"
	"net/http"
	"path"
	"strconv"
	"time"

	"connectrpc.com/connect"

	"dataguard/internal/platform/metrics"
)

var (
	durationBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30}
	// Delays run from a live tail to an agent that was offline for a day.
	delayBuckets = []float64{0.5, 1, 2, 5, 10, 30, 60, 300, 900, 3600, 21600, 86400}
	statuses     = []string{
		"200", "201", "202", "204", "304", "400", "401", "403", "404", "405", "409", "413", "422", "429",
		"500", "502", "503", "504", "1xx", "2xx", "3xx", "4xx", "5xx",
	}
)

// Server records the server's metrics. A nil *Server records nothing.
type Server struct {
	registry      *metrics.Registry
	agentRequests *metrics.Counter
	agentDuration *metrics.Histogram
	apiRequests   *metrics.Counter
	apiDuration   *metrics.Histogram
	ingested      *metrics.Counter
	deliveryDelay *metrics.Histogram
	ingestBatches *metrics.Counter
}

// New registers the server's metrics.
func New() *Server {
	registry := metrics.New("dataguard_server")
	return &Server{
		registry: registry,
		agentRequests: registry.Counter("agent_requests_total",
			"Agent RPC by procedure and outcome; code ok means success.",
			metrics.Code("procedure"), metrics.Code("code")),
		agentDuration: registry.Histogram("agent_request_duration_seconds",
			"Agent RPC handling time.", durationBuckets, metrics.Code("procedure")),
		apiRequests: registry.Counter("api_requests_total",
			"REST requests by route template and status.",
			metrics.Route("route"), metrics.Enum("status", statuses...)),
		apiDuration: registry.Histogram("api_request_duration_seconds",
			"REST handling time by route template.", durationBuckets, metrics.Route("route")),
		ingested: registry.Counter("events_ingested_total",
			"Events accepted from agents: stored, or already stored by an earlier delivery.",
			metrics.Enum("result", "stored", "duplicate")),
		deliveryDelay: registry.Histogram("event_delivery_delay_seconds",
			"Time from the event in the source log to its storage in the center.", delayBuckets),
		ingestBatches: registry.Counter("ingest_batches_total", "Event batches stored."),
	}
}

// Handler serves the metrics.
func (s *Server) Handler() http.Handler { return s.registry.Handler() }

// Gather returns the current samples, for tests.
func (s *Server) Gather() (map[string]float64, error) { return s.registry.Gather() }

// Ingested implements audit.Observer.
func (s *Server) Ingested(stored, duplicates int, delays []time.Duration) {
	if s == nil {
		return
	}
	s.ingestBatches.Inc()
	s.ingested.Add(float64(stored), "stored")
	s.ingested.Add(float64(duplicates), "duplicate")
	for _, delay := range delays {
		s.deliveryDelay.Observe(max(delay, 0).Seconds())
	}
}

// AgentInterceptor counts agent RPC. It must be the outermost interceptor, so a
// call refused by authorization is counted too.
func (s *Server) AgentInterceptor() connect.UnaryInterceptorFunc {
	return func(next connect.UnaryFunc) connect.UnaryFunc {
		return func(ctx context.Context, request connect.AnyRequest) (connect.AnyResponse, error) {
			if s == nil {
				return next(ctx, request)
			}
			started := time.Now()
			response, err := next(ctx, request)
			procedure := path.Base(request.Spec().Procedure)
			code := "ok"
			if err != nil {
				code = connect.CodeOf(err).String()
			}
			s.agentRequests.Inc(procedure, code)
			s.agentDuration.Observe(time.Since(started).Seconds(), procedure)
			return response, err
		}
	}
}

// API counts REST requests by the route template the router would pick, never by
// the path itself, which carries identifiers.
func (s *Server) API(router *http.ServeMux, next http.Handler) http.Handler {
	if s == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, route := router.Handler(r)
		if route == "" {
			route = "/unmatched"
		}
		recorder := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		started := time.Now()
		next.ServeHTTP(recorder, r)
		s.apiRequests.Inc(route, statusLabel(recorder.status))
		s.apiDuration.Observe(time.Since(started).Seconds(), route)
	})
}

func statusLabel(status int) string {
	label := strconv.Itoa(status)
	for _, known := range statuses {
		if known == label {
			return label
		}
	}
	return strconv.Itoa(status/100) + "xx"
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}
