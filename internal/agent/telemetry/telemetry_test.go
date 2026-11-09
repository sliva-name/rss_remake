package telemetry_test

import (
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"dataguard/internal/agent/telemetry"
	"dataguard/internal/contract/egress"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

const (
	observing   = "0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e1f"
	unavailable = "0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e20"
	degraded    = "0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e21"
	refused     = "0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e22"
)

type state struct{}

func (state) Health() (*agentv1.QueueHealth, []*agentv1.AuditSourceHealth) {
	return &agentv1.QueueHealth{PendingEvents: 7, PendingBytes: 900, CapacityBytes: 1000}, []*agentv1.AuditSourceHealth{
		{SourceId: observing, State: agentv1.AuditSourceState_AUDIT_SOURCE_STATE_OBSERVING, PositionReadAt: timestamppb.New(time.Now().Add(-time.Minute))},
		{SourceId: unavailable, State: agentv1.AuditSourceState_AUDIT_SOURCE_STATE_UNAVAILABLE, ReasonCode: "LOG_UNREADABLE"},
		{SourceId: degraded, State: agentv1.AuditSourceState_AUDIT_SOURCE_STATE_DEGRADED, ReasonCode: "QUEUE_FULL"},
	}
}

func (state) RefusalCodes() map[string]string {
	return map[string]string{refused: "TARGET_NOT_ALLOWED"}
}

func (state) CertificateExpiry() (time.Time, error) { return time.Unix(1_800_000_000, 0), nil }
func (state) PolicyVersion() uint64                 { return 4 }
func (state) SourcesVersion() uint64                { return 9 }

// The failure table of ARCHITECTURE.md, as an operator sees it in the metrics.
func TestFailuresAreVisibleInMetrics(t *testing.T) {
	observer := telemetry.New()
	observer.Watch(state{}, state{}, state{})
	observer.Request("SubmitEvents", connect.NewError(connect.CodeUnavailable, "down"))
	observer.Request("Heartbeat", nil)
	observer.Request("SubmitEvents", egress.ErrBlocked)
	observer.Request("PullJobs", connect.NewError(connect.CodeFailedPrecondition, "CONTRACT_UNSUPPORTED"))
	observer.Rejected("policy", "rollback")

	samples, err := observer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]float64{
		"dataguard_agent_queue_pending_events": 7,
		"dataguard_agent_queue_pending_bytes":  900,
		"dataguard_agent_audit_source_state|source_id=" + observing + "|state=AUDIT_SOURCE_STATE_OBSERVING":     1,
		"dataguard_agent_audit_source_state|source_id=" + unavailable + "|state=AUDIT_SOURCE_STATE_UNAVAILABLE": 1,
		"dataguard_agent_audit_source_state|source_id=" + unavailable + "|state=AUDIT_SOURCE_STATE_OBSERVING":   0,
		"dataguard_agent_audit_source_reason|reason=QUEUE_FULL|source_id=" + degraded:                           1,
		"dataguard_agent_source_refused|code=TARGET_NOT_ALLOWED|source_id=" + refused:                           1,
		"dataguard_agent_center_requests_total|code=unavailable|procedure=SubmitEvents":                         1,
		"dataguard_agent_center_requests_total|code=blocked|procedure=SubmitEvents":                             1,
		"dataguard_agent_center_requests_total|code=failed_precondition|procedure=PullJobs":                     1,
		"dataguard_agent_center_requests_total|code=ok|procedure=Heartbeat":                                     1,
		"dataguard_agent_center_documents_rejected_total|document=policy|reason=rollback":                       1,
		"dataguard_agent_certificate_expiry_timestamp_seconds":                                                  1_800_000_000,
		"dataguard_agent_sources_version":                                                                       9,
	} {
		if got, found := samples[key]; !found || got != want {
			t.Errorf("%s = %v (present %v), want %v", key, got, found, want)
		}
	}
	if age := samples["dataguard_agent_audit_position_age_seconds|source_id="+observing]; age < 59 || age > 120 {
		t.Errorf("position age = %v", age)
	}
	if samples["dataguard_agent_center_last_success_timestamp_seconds"] < float64(time.Now().Add(-time.Minute).Unix()) {
		t.Error("a successful call must move the last success time")
	}
}

func TestNilMetricsRecordNothing(t *testing.T) {
	var observer *telemetry.Agent
	observer.Request("Heartbeat", nil)
	observer.Queued([]*agentv1.AuditEvent{{EventType: agentv1.EventType_EVENT_TYPE_AUDIT_GAP, Gap: &agentv1.AuditGap{}}})
	observer.Blocked("AuditEvent")
	observer.Delivered(1)
	observer.Rejected("sources", "invalid")
	observer.Watch(state{}, state{}, state{})
}
