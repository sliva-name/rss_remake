//go:build integration

package integration_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"dataguard/internal/agent/center"
	"dataguard/internal/agent/runtime"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/pki"
	"dataguard/internal/platform/safelog"
)

type noSources struct{}

func (noSources) Probe(context.Context) []*agentv1.SourceReport { return nil }

// ROADMAP.md, stage 1: after the policy key is replaced, enrolled agents take
// new policies without enrolling again, and what the old key signs is refused.
func TestAgentFollowsARotatedPolicyKey(t *testing.T) {
	ctx := t.Context()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	agent := platform.enroll(t, created.ID, environment.ID)
	if _, err := platform.app.Policies.Publish(ctx, created.ID, "tester", nil, &agentv1.ScanBudget{MaxConnections: 1}); err != nil {
		t.Fatal(err)
	}

	if epoch, err := pki.RotatePolicyKey(platform.pkiDir); err != nil || epoch != 2 {
		t.Fatalf("rotate: %d, %v", epoch, err)
	}
	// A restarted server signs with the new key; the first one still runs on the old.
	restarted := platform.secondInstance(t)
	client, err := center.New(restarted.agents.URL, platform.caFile, agent.store, agent.metrics)
	if err != nil {
		t.Fatal(err)
	}
	control := runtime.NewControl(runtime.Options{
		Client: client, Identity: agent.store, Prober: noSources{}, Version: "test",
		HeartbeatInterval: 100 * time.Millisecond, Logger: safelog.Discard(), Metrics: agent.metrics,
	})
	loop, stop := context.WithCancel(ctx)
	var running sync.WaitGroup
	running.Go(func() { control.Run(loop) })
	t.Cleanup(func() {
		stop()
		running.Wait()
	})

	waitFor(t, "the agent takes the new key and the policy signed again with it", func() bool {
		return agent.store.PolicyKeyEpoch() == 2 && agent.store.PolicyVersion() == 1
	})
	if _, err := restarted.app.Policies.Publish(ctx, created.ID, "tester", nil, &agentv1.ScanBudget{MaxConnections: 2}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "a policy published after rotation", func() bool { return agent.store.PolicyVersion() == 2 })

	shown, err := restarted.app.Fleet.GetAgent(ctx, created.ID, agent.store.AgentID())
	if err != nil || shown.PolicyKeyEpoch != 2 {
		t.Fatalf("the center does not see the agent on epoch 2: %d, %v", shown.PolicyKeyEpoch, err)
	}
	// The server started before rotation still signs with the old key: the agent
	// refuses it, as it would refuse anyone who got hold of that key.
	stale, err := agent.client.GetSources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.store.AcceptSources(stale.GetSourceList(), stale.GetSignature()); !errors.Is(err, pki.ErrBadSignature) {
		t.Fatalf("a list signed by the retired key: %v", err)
	}
}

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting: %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
