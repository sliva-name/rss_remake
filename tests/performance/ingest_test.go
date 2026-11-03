//go:build performance

package performance_test

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"dataguard/internal/core/audit"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/safelog"
	"dataguard/internal/server/broker"
	"dataguard/internal/server/storage/clickhouse"
	"dataguard/internal/server/storage/postgres"
	"dataguard/internal/testkit/stand"
)

// Targets of ROADMAP.md, stage 0: one server instance takes the reference peak
// with room to spare, and an event reaches ClickHouse within half a minute.
const (
	ingestTarget = 2_000 // events per second
	delayTarget  = 30 * time.Second
	ingestAgents = 8
	agentBatches = 50
	agentBatch   = 500 // the agent's own batch size
)

// ownerCatalog says each agent owns one source with no classified columns.
type ownerCatalog map[uuid.UUID]uuid.UUID

func (c ownerCatalog) AgentSources(_ context.Context, _, agentID uuid.UUID) ([]uuid.UUID, error) {
	return []uuid.UUID{c[agentID]}, nil
}

func (ownerCatalog) ColumnsOf(context.Context, uuid.UUID, uuid.UUID) (map[audit.ColumnKey]audit.ColumnInfo, error) {
	return map[audit.ColumnKey]audit.ColumnInfo{}, nil
}

func (ownerCatalog) CatalogVersion(context.Context, uuid.UUID, uuid.UUID) (time.Time, error) {
	return time.Time{}, nil
}

// delays records the time from the event to its storage.
type delays struct {
	mu     sync.Mutex
	values []time.Duration
	stored int
}

func (d *delays) Accepted(int) {}

func (d *delays) Ingested(stored, _ int, observed []time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stored += stored
	d.values = append(d.values, observed...)
}

func (d *delays) snapshot() (int, []time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.stored, slices.Clone(d.values)
}

// TestIngestThroughTheBrokerKeepsUpWithTheTarget sends agent batches concurrently
// through the whole server path: validation, broker, consumer, duplicate check
// and ClickHouse.
func TestIngestThroughTheBrokerKeepsUpWithTheTarget(t *testing.T) {
	ctx := context.Background()
	_, runtimeDSN := stand.CenterDatabase(t)
	locks, err := postgres.Open(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(locks.Close)
	events, err := clickhouse.Open(ctx, stand.CenterEvents(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = events.Close() })
	settings := stand.CenterBroker(t)
	publisher, err := broker.NewPublisher(settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(publisher.Close)

	catalog := ownerCatalog{}
	for range ingestAgents {
		catalog[uuid.New()] = uuid.New()
	}
	observer := &delays{}
	service := audit.NewService(catalog, locks, events, publisher, observer)
	consumer := broker.NewConsumer(settings, service.Store, nil, safelog.Discard())
	consuming, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		consumer.Run(consuming)
	}()
	t.Cleanup(func() {
		stop()
		<-done
	})

	tenantID := uuid.New()
	total := ingestAgents * agentBatches * agentBatch
	started := time.Now()
	var group sync.WaitGroup
	for agentID, sourceID := range catalog {
		group.Go(func() {
			for range agentBatches {
				batch := make([]*agentv1.AuditEvent, agentBatch)
				for i := range batch {
					batch[i] = &agentv1.AuditEvent{
						EventId: uuid.NewString(), SourceId: sourceID.String(), EventTime: timestamppb.Now(),
						EventType: agentv1.EventType_EVENT_TYPE_DATA_ACCESS,
						Actor:     &agentv1.Actor{DatabasePrincipal: "svc_load", IdentityConfidence: agentv1.IdentityConfidence_IDENTITY_CONFIDENCE_DB_PRINCIPAL_ONLY},
					}
				}
				if _, err := service.Ingest(ctx, tenantID, agentID, batch); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	group.Wait()
	accepted := time.Since(started)
	deadline := time.Now().Add(5 * time.Minute)
	for {
		stored, _ := observer.snapshot()
		if stored >= total {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("stored %d of %d", stored, total)
		}
		time.Sleep(100 * time.Millisecond)
	}
	finished := time.Since(started)
	stored, observed := observer.snapshot()
	slices.Sort(observed)
	p95 := percentile(observed, 0.95)
	acceptRate := float64(total) / accepted.Seconds()
	storeRate := float64(stored) / finished.Seconds()
	t.Logf("ingest       %d events from %d agents: accepted at %.0f/s, stored at %.0f/s, delay p50 %s, p95 %s",
		total, ingestAgents, acceptRate, storeRate, percentile(observed, 0.5).Round(time.Millisecond), p95.Round(time.Millisecond))
	if stored != total {
		t.Errorf("stored %d events, want exactly %d", stored, total)
	}
	if storeRate < ingestTarget {
		t.Errorf("stored at %.0f events/s, below the target %d", storeRate, ingestTarget)
	}
	if p95 > delayTarget {
		t.Errorf("delay p95 %s exceeds the target %s", p95, delayTarget)
	}
}
