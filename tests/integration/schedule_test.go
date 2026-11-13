//go:build integration

package integration_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/proto"

	"dataguard/internal/core/fleet"
	"dataguard/internal/core/scan"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/gen/restapi"
	"dataguard/internal/server/api"
	"dataguard/internal/server/app"
)

// The center queues scans by schedule by itself: one per run however many
// server instances run the scheduler, none while the previous scan of the
// source still waits for its agent, and none for a revoked agent. Only an
// administrator sets a schedule, and the journal records who did.
func TestScheduledScansAreQueuedOncePerRun(t *testing.T) {
	ctx := t.Context()
	platform := startPlatform(t)
	second := platform.secondInstance(t)
	created, environment := platform.newTenant(t, "Acme")
	platform.authn["admin"] = api.Principal{Subject: "s-ivanova", Name: "ivanova", TenantID: created.ID, Roles: []string{api.RoleTenantAdmin}}
	platform.authn["analyst"] = api.Principal{Subject: "s-sidorova", Name: "sidorova", TenantID: created.ID, Roles: []string{api.RoleSecurityAnalyst}}
	agent := platform.enroll(t, created.ID, environment.ID)
	sourceIDs := make([]uuid.UUID, 0, 10)
	for i := range 10 {
		definition := placeholderSource()
		definition.Name = fmt.Sprintf("crm-%d", i)
		sourceIDs = append(sourceIDs, platform.addSource(t, agent, definition))
	}
	schedulePath := func(id uuid.UUID) string { return "/api/v1/sources/" + id.String() + "/scan-schedule" }

	// Every hour, first run a little under an hour ago: the next is two seconds away.
	body := fmt.Sprintf(`{"everyHours":1,"firstRunAt":%q}`, time.Now().Add(-time.Hour+2*time.Second).UTC().Format(time.RFC3339Nano))
	if status, payload := restCall(t, platform, http.MethodPut, schedulePath(sourceIDs[0]), "analyst", body); status != http.StatusForbidden {
		t.Fatalf("an analyst set a schedule: %d %s", status, payload)
	}
	for _, id := range sourceIDs {
		status, payload := restCall(t, platform, http.MethodPut, schedulePath(id), "admin", body)
		if status != http.StatusOK {
			t.Fatalf("set schedule: %d %s", status, payload)
		}
		var schedule restapi.ScanSchedule
		if err := json.Unmarshal(payload, &schedule); err != nil {
			t.Fatal(err)
		}
		if until := time.Until(schedule.NextRunAt); schedule.EveryHours != 1 || until <= 0 || until > 3*time.Second {
			t.Fatalf("schedule = %+v, next run in %v", schedule, until)
		}
	}

	// Both instances' schedulers take the due sources, and more callers race
	// them head on: a source must still get exactly one scan.
	time.Sleep(2 * time.Second)
	start := make(chan struct{})
	var racing sync.WaitGroup
	for _, instance := range []*app.App{platform.app, second.app} {
		for range 4 {
			racing.Go(func() {
				<-start
				if _, err := instance.Scans.RunSchedules(ctx, created.ID); err != nil {
					t.Error(err)
				}
			})
		}
	}
	close(start)
	racing.Wait()
	jobs := awaitJobs(t, platform, created.ID, sourceIDs, 1)
	for _, job := range jobs {
		if !job.Scheduled || job.RequestedBy != "" || job.Status != scan.StatusPending {
			t.Fatalf("scheduled job = %+v", job)
		}
	}
	for _, id := range sourceIDs {
		source, err := platform.app.Fleet.GetSource(ctx, created.ID, id)
		if err != nil {
			t.Fatal(err)
		}
		if until := time.Until(source.ScanSchedule.NextRun); until < 59*time.Minute || until > time.Hour {
			t.Fatalf("next run of %s in %v, want the next hour", source.Key, until)
		}
	}

	// The agent has not taken the scans yet when the next run comes: the
	// schedule moves on without a second scan.
	owner, err := pgx.Connect(ctx, platform.ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(ctx) })
	makeDue := func() {
		t.Helper()
		const due = `UPDATE sources SET next_scan_at = now() - interval '1 minute' WHERE id = ANY($1) AND next_scan_at IS NOT NULL`
		if _, err := owner.Exec(ctx, due, sourceIDs); err != nil {
			t.Fatal(err)
		}
	}
	makeDue()
	awaitScheduleMoved(t, platform, created.ID, sourceIDs)
	awaitJobs(t, platform, created.ID, sourceIDs, 1)

	// Once the scans are done, the next run queues the next ones.
	if _, err := owner.Exec(ctx, `UPDATE scan_jobs SET status = 'completed', finished_at = now() WHERE source_id = ANY($1)`, sourceIDs); err != nil {
		t.Fatal(err)
	}
	makeDue()
	awaitJobs(t, platform, created.ID, sourceIDs, 2)

	var listed []restapi.Scan
	if status, payload := restCall(t, platform, http.MethodGet, "/api/v1/scans?limit=200", "analyst", ""); status != http.StatusOK || json.Unmarshal(payload, &listed) != nil {
		t.Fatalf("list scans: %d %s", status, payload)
	}
	for _, item := range listed {
		if !item.Scheduled {
			t.Fatalf("a scheduled scan is listed as requested: %+v", item)
		}
	}
	samples := map[string]float64{}
	for _, metrics := range []func() (map[string]float64, error){platform.metrics.Gather, second.metrics.Gather} {
		gathered, err := metrics()
		if err != nil {
			t.Fatal(err)
		}
		for key, value := range gathered {
			samples[key] += value
		}
	}
	if samples["dataguard_server_scans_scheduled_total"] == 0 ||
		samples["dataguard_server_background_runs_total|outcome=ok|task=scan_schedule"] == 0 ||
		samples["dataguard_server_background_runs_total|outcome=error|task=scan_schedule"] != 0 {
		t.Fatalf("scheduler metrics: %v", samples)
	}

	// A source turned back to manual scans keeps none, and turning it off
	// twice is not two actions.
	for range 2 {
		if status, payload := restCall(t, platform, http.MethodDelete, schedulePath(sourceIDs[0]), "admin", ""); status != http.StatusNoContent {
			t.Fatalf("delete schedule: %d %s", status, payload)
		}
	}
	var manual restapi.Source
	if status, payload := restCall(t, platform, http.MethodGet, "/api/v1/sources/"+sourceIDs[0].String(), "analyst", ""); status != http.StatusOK || json.Unmarshal(payload, &manual) != nil || manual.ScanSchedule != nil {
		t.Fatalf("source after delete: %d %s", status, payload)
	}
	var journal []restapi.OperatorAction
	if status, payload := restCall(t, platform, http.MethodGet, "/api/v1/operator-actions?objectId="+sourceIDs[0].String(), "admin", ""); status != http.StatusOK || json.Unmarshal(payload, &journal) != nil {
		t.Fatalf("journal: %d %s", status, payload)
	}
	var actions []string
	for _, entry := range journal {
		if entry.Action == restapi.OperatorActionActionScanScheduleUpdate && (entry.ActorName != "ivanova" || entry.Details["every_hours"] != "1" || entry.ObjectLabel != "crm-0") {
			t.Fatalf("schedule entry = %+v", entry)
		}
		if entry.Action != restapi.OperatorActionActionSourceCreate {
			actions = append(actions, string(entry.Action))
		}
	}
	if fmt.Sprint(actions) != "[scan_schedule.delete scan_schedule.update]" {
		t.Fatalf("journal of the source: %v", actions)
	}

	// A draft is only being checked: it gets a schedule once it is saved.
	draft := placeholderSource()
	draft.Name, draft.ProbeOnly = "probe", true
	if status, payload := restCall(t, platform, http.MethodPut, schedulePath(platform.addSource(t, agent, draft)), "admin", body); status != http.StatusNotFound {
		t.Fatalf("a draft got a schedule: %d %s", status, payload)
	}

	// A revoked agent takes no scans: queueing them would only leave them waiting.
	if err := platform.app.Fleet.Revoke(ctx, created.ID, agent.store.AgentID()); err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(ctx, `UPDATE scan_jobs SET status = 'completed', finished_at = now() WHERE source_id = ANY($1)`, sourceIDs); err != nil {
		t.Fatal(err)
	}
	makeDue()
	time.Sleep(5 * taskPeriod)
	awaitJobs(t, platform, created.ID, sourceIDs[1:], 2)
}

// awaitJobs waits until each source has want scans and none has more.
func awaitJobs(t *testing.T, platform *platform, tenantID uuid.UUID, sourceIDs []uuid.UUID, want int) []scan.Job {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		jobs, err := platform.app.Scans.List(t.Context(), tenantID, 200)
		if err != nil {
			t.Fatal(err)
		}
		perSource := map[uuid.UUID]int{}
		var ours []scan.Job
		for _, job := range jobs {
			perSource[job.SourceID]++
			ours = append(ours, job)
		}
		complete := true
		for _, id := range sourceIDs {
			if perSource[id] > want {
				t.Fatalf("source %s has %d scans, want %d", id, perSource[id], want)
			}
			complete = complete && perSource[id] == want
		}
		if complete {
			return ours
		}
		if time.Now().After(deadline) {
			t.Fatalf("scans per source: %v, want %d each", perSource, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// awaitScheduleMoved waits until the scheduler has moved every source's next
// run ahead of now.
func awaitScheduleMoved(t *testing.T, platform *platform, tenantID uuid.UUID, sourceIDs []uuid.UUID) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for _, id := range sourceIDs {
		for {
			source, err := platform.app.Fleet.GetSource(t.Context(), tenantID, id)
			if err != nil {
				t.Fatal(err)
			}
			if source.ScanSchedule.NextRun.After(time.Now()) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the next run of %s stayed at %v", source.Key, source.ScanSchedule.NextRun)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
}

// A draft left by a closed browser leaves its agent's list by itself, and its
// name is free again; a draft being checked right now stays.
func TestAbandonedDraftIsRemovedByTheCenter(t *testing.T) {
	ctx := t.Context()
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	agent := platform.enroll(t, created.ID, environment.ID)
	fresh, abandoned := placeholderSource(), placeholderSource()
	fresh.Name, fresh.ProbeOnly = "fresh", true
	abandoned.Name, abandoned.ProbeOnly = "abandoned", true
	freshID := platform.addSource(t, agent, fresh)
	abandonedID := platform.addSource(t, agent, abandoned)
	before, err := platform.app.Fleet.SourceList(ctx, created.ID, agent.store.AgentID())
	if err != nil {
		t.Fatal(err)
	}

	owner, err := pgx.Connect(ctx, platform.ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(ctx) })
	if _, err := owner.Exec(ctx, `UPDATE sources SET updated_at = now() - interval '2 hours' WHERE id = $1`, abandonedID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, err := platform.app.Fleet.GetSource(ctx, created.ID, abandonedID)
		if errors.Is(err, fleet.ErrNotFound) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if time.Now().After(deadline) {
			t.Fatal("an abandoned draft was not removed")
		}
		time.Sleep(50 * time.Millisecond)
	}

	after, err := platform.app.Fleet.SourceList(ctx, created.ID, agent.store.AgentID())
	if err != nil {
		t.Fatal(err)
	}
	var list agentv1.SourceList
	if err := proto.Unmarshal(after.Payload, &list); err != nil {
		t.Fatal(err)
	}
	if after.Version <= before.Version || len(list.GetSources()) != 1 || list.GetSources()[0].GetSourceId() != freshID.String() {
		t.Fatalf("list after removal: version %d (was %d), %v", after.Version, before.Version, list.GetSources())
	}
	abandoned.ProbeOnly = false
	platform.addSource(t, agent, abandoned)
}
