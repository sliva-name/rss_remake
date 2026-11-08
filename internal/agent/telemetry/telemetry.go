// Package telemetry holds the agent's metrics (ADR-0008). Every failure in the
// failure table of ARCHITECTURE.md shows up here, and nothing here names a value,
// an object or a person: labels are enumerations, codes and source ids.
package telemetry

import (
	"errors"
	"net/http"
	"slices"
	"time"

	"connectrpc.com/connect/v2"

	"dataguard/internal/contract/egress"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/metrics"
)

// Health is what the audit runtime already reports in heartbeats.
type Health interface {
	Health() (*agentv1.QueueHealth, []*agentv1.AuditSourceHealth)
}

// Refusals lists the sources the agent declined to open, by id, with the code.
type Refusals interface {
	RefusalCodes() map[string]string
}

// Identity is the agent's registration state.
type Identity interface {
	CertificateExpiry() (time.Time, error)
	PolicyVersion() uint64
	SourcesVersion() uint64
}

// Agent records the agent's metrics. A nil *Agent records nothing, so components
// built without metrics, as in most tests, need no special case.
type Agent struct {
	registry    *metrics.Registry
	requests    *metrics.Counter
	lastSuccess *metrics.Gauge
	blocked     *metrics.Counter
	queued      *metrics.Counter
	gaps        *metrics.Counter
	lost        *metrics.Counter
	delivered   *metrics.Counter
	rejected    *metrics.Counter
}

func enumNames(names map[int32]string) []string {
	values := make([]string, 0, len(names))
	for _, name := range names {
		values = append(values, name)
	}
	slices.Sort(values)
	return values
}

var (
	eventTypes   = enumNames(agentv1.EventType_name)
	gapReasons   = enumNames(agentv1.GapReason_name)
	sourceStates = enumNames(agentv1.AuditSourceState_name)
)

// New registers the agent's metrics.
func New() *Agent {
	registry := metrics.New("dataguard_agent")
	return &Agent{
		registry: registry,
		requests: registry.Counter("center_requests_total",
			"Calls to the center by procedure and outcome; code ok means success.",
			metrics.Code("procedure"), metrics.Code("code")),
		lastSuccess: registry.Gauge("center_last_success_timestamp_seconds",
			"When a call to the center last succeeded."),
		blocked: registry.Counter("egress_blocked_total",
			"Messages the egress guard refused to send or to queue, by message type.",
			metrics.Code("message")),
		queued: registry.Counter("events_queued_total",
			"Events written to the durable queue, by type.",
			metrics.Enum("type", eventTypes...)),
		gaps: registry.Counter("audit_gaps_total",
			"Audit gaps found by the collectors, by reason.",
			metrics.Enum("reason", gapReasons...)),
		lost: registry.Counter("audit_lost_events_total",
			"Records known to be lost, by gap reason. Gaps of unknown size add nothing.",
			metrics.Enum("reason", gapReasons...)),
		delivered: registry.Counter("events_delivered_total",
			"Events the center confirmed durable and the queue released."),
		rejected: registry.Counter("center_documents_rejected_total",
			"Policies and source lists from the center that failed verification.",
			metrics.Enum("document", "policy", "sources"), metrics.Enum("reason", "bad_signature", "rollback", "invalid")),
	}
}

// Handler serves the metrics.
func (a *Agent) Handler() http.Handler { return a.registry.Handler() }

// Gather returns the current samples, for tests.
func (a *Agent) Gather() (map[string]float64, error) { return a.registry.Gather() }

// Request records the outcome of a call to the center.
func (a *Agent) Request(procedure string, err error) {
	if a == nil {
		return
	}
	code := "ok"
	switch {
	case errors.Is(err, egress.ErrBlocked):
		code = "blocked"
	case err != nil:
		code = connect.CodeOf(err).String()
	default:
		a.lastSuccess.Set(float64(time.Now().Unix()))
	}
	a.requests.Inc(procedure, code)
}

// Blocked records a message the egress guard refused.
func (a *Agent) Blocked(message string) {
	if a == nil {
		return
	}
	a.blocked.Inc(message)
}

// Queued records events after the queue committed them.
func (a *Agent) Queued(events []*agentv1.AuditEvent) {
	if a == nil {
		return
	}
	for _, event := range events {
		a.queued.Inc(event.GetEventType().String())
		if gap := event.GetGap(); gap != nil {
			reason := gap.GetReason().String()
			a.gaps.Inc(reason)
			a.lost.Add(float64(gap.GetLostEvents()), reason)
		}
	}
}

// Delivered records events the center confirmed.
func (a *Agent) Delivered(count int) {
	if a == nil {
		return
	}
	a.delivered.Add(float64(count))
}

// Rejected records a policy or source list that failed verification.
func (a *Agent) Rejected(document, reason string) {
	if a == nil {
		return
	}
	a.rejected.Inc(document, reason)
}

// Watch exposes state the agent already keeps. It is read on every scrape, so a
// metric cannot drift from what the heartbeat reports.
func (a *Agent) Watch(health Health, refusals Refusals, identity Identity) {
	if a == nil {
		return
	}
	queue := func(pick func(*agentv1.QueueHealth) uint64) func(metrics.Emit) {
		return func(emit metrics.Emit) {
			state, _ := health.Health()
			emit(float64(pick(state)))
		}
	}
	a.registry.Snapshot("queue_pending_events", "Events waiting in the durable queue.",
		queue((*agentv1.QueueHealth).GetPendingEvents))
	a.registry.Snapshot("queue_pending_bytes", "Bytes waiting in the durable queue.",
		queue((*agentv1.QueueHealth).GetPendingBytes))
	a.registry.Snapshot("queue_capacity_bytes", "Capacity of the durable queue.",
		queue((*agentv1.QueueHealth).GetCapacityBytes))

	a.registry.Snapshot("audit_source_state",
		"Collector state per source, one series per state; 1 marks the current one. Silence is activity only in OBSERVING.",
		func(emit metrics.Emit) {
			_, sources := health.Health()
			for _, source := range sources {
				for _, state := range sourceStates {
					value := 0.0
					if source.GetState().String() == state {
						value = 1
					}
					emit(value, source.GetSourceId(), state)
				}
			}
		}, metrics.UUID("source_id"), metrics.Enum("state", sourceStates...))
	a.registry.Snapshot("audit_source_reason", "Why a collector is not observing; present only while it is not.",
		func(emit metrics.Emit) {
			_, sources := health.Health()
			for _, source := range sources {
				if source.GetReasonCode() != "" {
					emit(1, source.GetSourceId(), source.GetReasonCode())
				}
			}
		}, metrics.UUID("source_id"), metrics.Code("reason"))
	a.registry.Snapshot("audit_position_age_seconds", "Time since the collector last advanced its read position.",
		func(emit metrics.Emit) {
			_, sources := health.Health()
			for _, source := range sources {
				if at := source.GetPositionReadAt(); at != nil {
					emit(time.Since(at.AsTime()).Seconds(), source.GetSourceId())
				}
			}
		}, metrics.UUID("source_id"))
	a.registry.Snapshot("source_refused", "Sources from the center the agent did not open, with the code it reported.",
		func(emit metrics.Emit) {
			for id, code := range refusals.RefusalCodes() {
				emit(1, id, code)
			}
		}, metrics.UUID("source_id"), metrics.Code("code"))

	a.registry.Snapshot("certificate_expiry_timestamp_seconds", "When the agent certificate expires.",
		func(emit metrics.Emit) {
			if expiry, err := identity.CertificateExpiry(); err == nil {
				emit(float64(expiry.Unix()))
			}
		})
	a.registry.Snapshot("policy_version", "Version of the accepted policy.",
		func(emit metrics.Emit) { emit(float64(identity.PolicyVersion())) })
	a.registry.Snapshot("sources_version", "Version of the accepted source list.",
		func(emit metrics.Emit) { emit(float64(identity.SourcesVersion())) })
}
