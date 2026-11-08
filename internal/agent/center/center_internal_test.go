package center

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connectinprocess"
	"github.com/google/uuid"

	"dataguard/internal/agent/telemetry"
	"dataguard/internal/contract/egress"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/gen/dataguard/agent/v1/agentv1connect"
)

type recordingCenter struct {
	agentv1connect.UnimplementedAgentServiceHandler
	heartbeats atomic.Int32
}

func (c *recordingCenter) Heartbeat(context.Context, *agentv1.HeartbeatRequest) (*agentv1.HeartbeatResponse, error) {
	c.heartbeats.Add(1)
	return &agentv1.HeartbeatResponse{}, nil
}

func heartbeat(messageID string) *agentv1.HeartbeatRequest {
	return &agentv1.HeartbeatRequest{Envelope: &agentv1.Envelope{
		SchemaVersion: schemaVersion, MessageId: messageID, TenantId: uuid.NewString(), AgentId: uuid.NewString(),
	}}
}

func TestBlockedMessageNeverReachesTheCenter(t *testing.T) {
	center := &recordingCenter{}
	server := connect.NewServer()
	agentv1connect.RegisterAgentServiceHandler(server, center)
	observer := telemetry.New()
	client := agentv1connect.NewAgentServiceClient(
		connect.NewClient(connectinprocess.New(server), metricsInterceptor(observer), egressInterceptor))

	if _, err := client.Heartbeat(t.Context(), heartbeat(uuid.NewString())); err != nil {
		t.Fatalf("heartbeat within the contract: %v", err)
	}
	if _, err := client.Heartbeat(t.Context(), heartbeat("not-a-uuid")); !errors.Is(err, egress.ErrBlocked) {
		t.Fatalf("heartbeat breaking the contract: %v", err)
	}
	if got := center.heartbeats.Load(); got != 1 {
		t.Fatalf("the center received %d heartbeats, want 1", got)
	}

	samples, err := observer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]float64{
		"dataguard_agent_center_requests_total|code=ok|procedure=Heartbeat":      1,
		"dataguard_agent_center_requests_total|code=blocked|procedure=Heartbeat": 1,
		"dataguard_agent_egress_blocked_total|message=HeartbeatRequest":          1,
	} {
		if got := samples[key]; got != want {
			t.Errorf("%s = %v, want %v", key, got, want)
		}
	}
}
