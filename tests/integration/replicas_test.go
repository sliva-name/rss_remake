//go:build integration

package integration_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"dataguard/internal/agent/center"
	"dataguard/internal/agent/config"
	"dataguard/internal/agent/identity"
	"dataguard/internal/agent/runtime"
	"dataguard/internal/core/policy"
	"dataguard/internal/core/scan"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/testkit/seed"
	"dataguard/internal/testkit/stand"
	"dataguard/internal/testkit/synthetic"
)

// balancer passes TCP connections to one backend at a time, like a layer-4 load
// balancer: mTLS must end at the server, which reads the agent from its
// certificate. Switching closes every open connection, as a failed instance does.
type balancer struct {
	listener net.Listener
	target   atomic.Value

	mu    sync.Mutex
	conns []net.Conn
}

func newBalancer(t *testing.T, target string) *balancer {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &balancer{listener: listener}
	b.target.Store(target)
	t.Cleanup(func() {
		_ = listener.Close()
		b.dropAll()
	})
	go b.accept(t.Context())
	return b
}

func (b *balancer) URL() string { return "https://" + b.listener.Addr().String() }

func (b *balancer) accept(ctx context.Context) {
	var dialer net.Dialer
	for {
		client, err := b.listener.Accept()
		if err != nil {
			return
		}
		backend, err := dialer.DialContext(ctx, "tcp", b.target.Load().(string))
		if err != nil {
			_ = client.Close()
			continue
		}
		b.mu.Lock()
		b.conns = append(b.conns, client, backend)
		b.mu.Unlock()
		go func() { _, _ = io.Copy(backend, client); _ = backend.Close() }()
		go func() { _, _ = io.Copy(client, backend); _ = client.Close() }()
	}
}

func (b *balancer) switchTo(target string) {
	b.target.Store(target)
	b.dropAll()
}

func (b *balancer) dropAll() {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, conn := range b.conns {
		_ = conn.Close()
	}
	b.conns = nil
}

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Host
}

// TestAgentMovesBetweenInstancesWithoutLossOrDuplicates runs a real agent
// through a balancer while connections to the instances keep breaking: deliveries
// cut after the insert and before the acknowledgement land on the other instance.
func TestAgentMovesBetweenInstancesWithoutLossOrDuplicates(t *testing.T) {
	ctx := context.Background()
	source := stand.PostgresSource(t)
	if err := seed.Tables(ctx, source.Admin, source.Dialect, 40, synthetic.New(21)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	first := startPlatform(t)
	second := first.secondInstance(t)
	targets := []string{hostOf(t, first.agents.URL), hostOf(t, second.agents.URL)}
	front := newBalancer(t, targets[0])

	created, environment := first.newTenant(t, "Acme")
	source.Config.AuditDirectory = stand.AuditDirectory(source.Dialect.Name)
	agent, ids := first.startAgent(t, first.enrollThrough(t, created.ID, environment.ID, front.URL()), source.Config)
	job, err := second.app.Scans.Request(ctx, created.ID, ids[0], "tester")
	if err != nil {
		t.Fatal(err)
	}
	if finished := waitForScan(t, first, created.ID, job.ID); finished.Status != scan.StatusCompleted {
		t.Fatalf("scan: %+v", finished)
	}
	agent.awaitObserving(t)

	countStatus := func() int {
		events, _ := first.search(t, created.ID, searchWindow())
		count := 0
		for _, event := range events {
			if strings.Contains(strings.Join(event.Columns, ","), seed.Users+".status") {
				count++
			}
		}
		return count
	}
	// Each phase moves the agent to the other instance by breaking its connections,
	// then waits until that phase's statements are stored, so both instances take
	// part whatever the timing of delivery.
	const phases, perPhase = 4, 10
	for phase := range phases {
		front.switchTo(targets[(phase+1)%2])
		for i := range perPhase {
			statement := fmt.Sprintf(`SELECT status, %d FROM %s`, phase*perPhase+i, seed.Users)
			if _, err := source.Admin.ExecContext(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
		want := (phase + 1) * perPhase
		deadline := time.Now().Add(auditWait)
		for countStatus() < want {
			if time.Now().After(deadline) {
				t.Fatalf("phase %d: delivered %d of %d across instances", phase, countStatus(), want)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	events, total := first.search(t, created.ID, searchWindow())
	identifiers := map[uuid.UUID]bool{}
	for _, event := range events {
		identifiers[event.ID] = true
	}
	if uint64(len(identifiers)) != total {
		t.Fatalf("%d unique of %d stored", len(identifiers), total)
	}
	// Ingest happens where the agent connects; storing, where the consumer owns the
	// agent's partition.
	accepted, stored := map[string]float64{}, map[string]float64{}
	for name, metrics := range map[string]func() (map[string]float64, error){"first": first.metrics.Gather, "second": second.metrics.Gather} {
		samples := gather(t, metrics)
		accepted[name] = samples["dataguard_server_events_accepted_total"]
		stored[name] = samples["dataguard_server_events_ingested_total|result=stored"]
	}
	if accepted["first"] == 0 || accepted["second"] == 0 {
		t.Fatalf("both instances must have accepted events: %v", accepted)
	}
	if uint64(stored["first"]+stored["second"]) != total {
		t.Fatalf("instances stored %v rows in total, the table holds %d", stored, total)
	}
	t.Logf("accepted by instance: %v, stored: %v, total %d", accepted, stored, total)
}

// TestInstancesAgreeUnderConcurrentRequests sends the same request to both
// instances at once wherever one of them answering wrongly would break a promise.
func TestInstancesAgreeUnderConcurrentRequests(t *testing.T) {
	ctx := context.Background()
	first := startPlatform(t)
	second := first.secondInstance(t)
	urls := []string{first.agents.URL, second.agents.URL}
	created, environment := first.newTenant(t, "Acme")

	// One token, two instances, two agents racing for it: exactly one enrolls.
	token, _, err := first.app.Fleet.CreateEnrollmentToken(ctx, created.ID, environment.ID)
	if err != nil {
		t.Fatal(err)
	}
	directories := []string{t.TempDir(), t.TempDir()}
	results := make([]error, len(urls))
	var group sync.WaitGroup
	for i := range urls {
		group.Go(func() {
			settings := &config.Config{StateDir: directories[i], Center: config.Center{URL: urls[i], CAFile: first.caFile}}
			results[i] = runtime.Enroll(ctx, settings, token, "1.0.0")
		})
	}
	group.Wait()
	winner := -1
	for i, err := range results {
		if err == nil {
			if winner >= 0 {
				t.Fatal("one enrollment token registered two agents")
			}
			winner = i
		}
	}
	if winner < 0 {
		t.Fatalf("no enrollment succeeded: %v", results)
	}
	store, err := identity.Open(directories[winner])
	if err != nil {
		t.Fatal(err)
	}
	clients := make([]*center.Client, len(urls))
	for i, url := range urls {
		if clients[i], err = center.New(url, first.caFile, store, nil); err != nil {
			t.Fatal(err)
		}
	}
	enrolled := enrolledAgent{client: clients[0], store: store, dir: directories[winner]}
	sourceID := first.addSource(t, enrolled, placeholderSource())

	t.Run("a batch sent to both instances is stored once", func(t *testing.T) {
		batch := make([]*agentv1.AuditEvent, 30)
		for i := range batch {
			batch[i] = &agentv1.AuditEvent{
				EventId: uuid.NewString(), SourceId: sourceID.String(),
				EventTime: timestamppb.Now(), EventType: agentv1.EventType_EVENT_TYPE_DATA_ACCESS,
			}
		}
		failures := make(chan error, 8)
		var group sync.WaitGroup
		for i := range 8 {
			group.Go(func() {
				if accepted, err := clients[i%2].SubmitEvents(ctx, batch); err != nil || len(accepted) != len(batch) {
					failures <- fmt.Errorf("accepted %d: %w", len(accepted), err)
				}
			})
		}
		group.Wait()
		close(failures)
		for err := range failures {
			t.Fatal(err)
		}
		first.awaitStored(t, created.ID, len(batch))
	})

	t.Run("each scan job is leased once", func(t *testing.T) {
		const jobs = 12
		requested := map[uuid.UUID]bool{}
		services := []*scan.Service{first.app.Scans, second.app.Scans}
		for i := range jobs {
			job, err := services[i%2].Request(ctx, created.ID, sourceID, "tester")
			if err != nil {
				t.Fatal(err)
			}
			requested[job.ID] = true
		}
		var mu sync.Mutex
		leased := map[string]int{}
		var group sync.WaitGroup
		for i := range 6 {
			group.Go(func() {
				for {
					found, err := clients[i%2].PullJobs(ctx, 1)
					if err != nil {
						t.Error(err)
						return
					}
					if len(found) == 0 {
						return
					}
					mu.Lock()
					for _, job := range found {
						leased[job.GetJobId()]++
					}
					mu.Unlock()
				}
			})
		}
		group.Wait()
		if len(leased) != jobs {
			t.Fatalf("leased %d distinct jobs of %d", len(leased), jobs)
		}
		for id, times := range leased {
			if times != 1 || !requested[uuid.MustParse(id)] {
				t.Fatalf("job %s leased %d times", id, times)
			}
		}
	})

	t.Run("policies published on both instances get distinct versions", func(t *testing.T) {
		versions := make([]uint64, 6)
		var group sync.WaitGroup
		for i := range versions {
			group.Go(func() {
				services := []*policy.Service{first.app.Policies, second.app.Policies}
				version, err := services[i%2].Publish(ctx, created.ID, "tester", nil, nil)
				if err != nil {
					t.Error(err)
				}
				versions[i] = version
			})
		}
		group.Wait()
		seen := map[uint64]bool{}
		for _, version := range versions {
			if seen[version] {
				t.Fatalf("two policies signed as version %d: %v", version, versions)
			}
			seen[version] = true
		}
		// Signed by one instance, verified against what the other serves.
		response, err := clients[1].GetPolicy(ctx)
		if err != nil {
			t.Fatal(err)
		}
		policy, err := store.AcceptPolicy(response.GetPolicy(), response.GetSignature())
		if err != nil || policy.GetVersion() != uint64(len(versions)) {
			t.Fatalf("policy from the second instance: %v, %v", policy.GetVersion(), err)
		}
		list, err := clients[1].GetSources(ctx)
		if err != nil {
			t.Fatal(err)
		}
		accepted, err := store.AcceptSources(list.GetSourceList(), list.GetSignature())
		if err != nil || len(accepted.GetSources()) != 1 {
			t.Fatalf("source list from the second instance: %v, %v", accepted, err)
		}
	})

	t.Run("a revocation on one instance stops the agent on the other", func(t *testing.T) {
		if err := first.app.Fleet.Revoke(ctx, created.ID, store.AgentID()); err != nil {
			t.Fatal(err)
		}
		_, err := clients[1].Heartbeat(ctx, &agentv1.HeartbeatRequest{AgentVersion: "1.0.0"})
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Fatalf("heartbeat after revocation: %v", err)
		}
	})
}
