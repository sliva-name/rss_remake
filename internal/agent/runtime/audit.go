package runtime

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"dataguard/internal/agent/center"
	"dataguard/internal/agent/collector"
	"dataguard/internal/agent/config"
	"dataguard/internal/agent/queue"
	"dataguard/internal/agent/sources"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/retry"
	"dataguard/sdk/go/appcontext"
)

const (
	sendBatchEvents  = 500
	sendBatchBytes   = 4 << 20
	sendIdleInterval = time.Second
	sourcesRecheck   = time.Second
)

// ContextVerifier checks application tokens against locally configured keys.
type ContextVerifier struct {
	keys map[string]ed25519.PublicKey
}

// NewContextVerifier loads the public keys of trusted applications.
func NewContextVerifier(applications []config.Application) (*ContextVerifier, error) {
	keys := make(map[string]ed25519.PublicKey, len(applications))
	for _, application := range applications {
		data, err := os.ReadFile(filepath.Clean(application.PublicKeyFile))
		if err != nil {
			return nil, fmt.Errorf("read key of application %s: %w", application.ID, err)
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if err != nil || len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("key of application %s is not a base64 ed25519 public key", application.ID)
		}
		keys[application.ID] = key
	}
	return &ContextVerifier{keys: keys}, nil
}

// Verify implements collector.Verifier.
func (v *ContextVerifier) Verify(token, databasePrincipal string, at time.Time) (subject, application, trace string, err error) {
	claims, err := appcontext.Verify(token, v.keys, databasePrincipal, at)
	if err != nil {
		return "", "", "", err
	}
	return claims.Subject, claims.Application, claims.Trace, nil
}

// Audit runs a collector per source and delivers the queue to the center.
type Audit struct {
	client   *center.Client
	registry *sources.Registry
	events   *queue.Queue
	verifier collector.Verifier
	logger   *slog.Logger
	backoff  retry.Backoff

	mu         sync.Mutex
	collectors map[string]*runningCollector
}

// runningCollector is one source's collector with what is needed to stop it.
type runningCollector struct {
	item     *collector.Collector
	revision uint64
	cancel   context.CancelFunc
	done     chan struct{}
	release  func()
}

// NewAudit creates the runtime.
func NewAudit(client *center.Client, registry *sources.Registry, events *queue.Queue, verifier collector.Verifier, logger *slog.Logger) *Audit {
	return &Audit{
		client: client, registry: registry, events: events, verifier: verifier, logger: logger,
		backoff: retry.Backoff{Base: backoffBase, Max: backoffMax}, collectors: map[string]*runningCollector{},
	}
}

// Run keeps one collector per audited source and delivers events until ctx
// ends. Collection never depends on the center being up.
func (a *Audit) Run(ctx context.Context) {
	var running sync.WaitGroup
	running.Go(func() { a.deliver(ctx) })
	defer func() {
		a.stopAll()
		running.Wait()
	}()
	for {
		a.reconcile(ctx)
		if !retry.Sleep(ctx, sourcesRecheck) {
			return
		}
	}
}

// reconcile stops collectors whose source was removed or changed, then starts
// the missing ones. A changed source resumes from its stored read position.
func (a *Audit) reconcile(ctx context.Context) {
	plans := a.registry.Plans()
	a.mu.Lock()
	var stale []*runningCollector
	for id, item := range a.collectors {
		if plan, ok := plans[id]; !ok || plan.Revision != item.revision {
			stale = append(stale, item)
			delete(a.collectors, id)
		}
	}
	a.mu.Unlock()
	for _, item := range stale {
		item.stop()
	}
	for id, plan := range plans {
		a.mu.Lock()
		_, started := a.collectors[id]
		a.mu.Unlock()
		if started || plan.Definition.AuditDirectory == "" {
			continue
		}
		source, release, ok := a.registry.Acquire(id)
		if !ok {
			continue
		}
		item := sources.NewCollector(plan.Definition, source, a.events, a.verifier, a.logger)
		if item == nil {
			release()
			continue
		}
		collectorContext, cancel := context.WithCancel(ctx)
		launched := &runningCollector{item: item, revision: plan.Revision, cancel: cancel, done: make(chan struct{}), release: release}
		a.mu.Lock()
		a.collectors[id] = launched
		a.mu.Unlock()
		go func() {
			defer close(launched.done)
			item.Run(collectorContext)
		}()
	}
}

func (r *runningCollector) stop() {
	r.cancel()
	<-r.done
	r.release()
}

func (a *Audit) stopAll() {
	a.mu.Lock()
	all := a.collectors
	a.collectors = map[string]*runningCollector{}
	a.mu.Unlock()
	for _, item := range all {
		item.stop()
	}
}

// Health implements HealthReporter.
func (a *Audit) Health() (*agentv1.QueueHealth, []*agentv1.AuditSourceHealth) {
	health := &agentv1.QueueHealth{}
	if stats, err := a.events.Stats(); err == nil {
		health.PendingEvents, health.PendingBytes, health.CapacityBytes = stats.PendingEvents, stats.PendingBytes, stats.CapacityBytes
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	reports := make([]*agentv1.AuditSourceHealth, 0, len(a.collectors))
	for _, running := range a.collectors {
		reports = append(reports, running.item.Health())
	}
	return health, reports
}

func (a *Audit) deliver(ctx context.Context) {
	failures := 0
	for {
		delivered, err := a.sendBatch(ctx)
		wait := time.Duration(0)
		switch {
		case err != nil && ctx.Err() == nil:
			wait = a.backoff.Delay(failures)
			failures++
			a.logger.Warn("events not delivered", "error", rpcError("submit events", err), "backoff", wait.String())
		case err == nil && delivered == 0:
			failures = 0
			wait = sendIdleInterval
		default:
			failures = 0
		}
		if ctx.Err() != nil || !retry.Sleep(ctx, wait) {
			return
		}
	}
}

// sendBatch removes only what the center confirmed durable.
func (a *Audit) sendBatch(ctx context.Context) (int, error) {
	items, err := a.events.Peek(sendBatchEvents, sendBatchBytes)
	if err != nil || len(items) == 0 {
		return 0, err
	}
	events := make([]*agentv1.AuditEvent, len(items))
	for i := range items {
		events[i] = items[i].Event
	}
	accepted, err := a.client.SubmitEvents(ctx, events)
	if err != nil {
		return 0, err
	}
	confirmed := make(map[string]bool, len(accepted))
	for _, id := range accepted {
		confirmed[id] = true
	}
	sequences := make([]uint64, 0, len(items))
	for i := range items {
		if confirmed[items[i].Event.GetEventId()] {
			sequences = append(sequences, items[i].Sequence)
		}
	}
	if len(sequences) == 0 {
		return 0, errors.New("center accepted nothing")
	}
	return len(sequences), a.events.Ack(sequences)
}
