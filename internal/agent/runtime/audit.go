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
	sendBatchEvents   = 500
	sendBatchBytes    = 4 << 20
	sendIdleInterval  = time.Second
	assignmentRecheck = time.Second
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
	collectors map[string]*collector.Collector
}

// NewAudit creates the runtime.
func NewAudit(client *center.Client, registry *sources.Registry, events *queue.Queue, verifier collector.Verifier, logger *slog.Logger) *Audit {
	return &Audit{
		client: client, registry: registry, events: events, verifier: verifier, logger: logger,
		backoff: retry.Backoff{Base: backoffBase, Max: backoffMax}, collectors: map[string]*collector.Collector{},
	}
}

// Run starts collectors as sources get ids and delivers events until ctx ends.
// Collection never depends on the center being up.
func (a *Audit) Run(ctx context.Context) {
	if err := a.registry.LoadAssignments(a.events); err != nil {
		a.logger.Warn("stored source assignments ignored", "reason", "unreadable")
	}
	var running sync.WaitGroup
	defer running.Wait()
	running.Go(func() { a.deliver(ctx) })
	for {
		a.startCollectors(ctx, &running)
		if !retry.Sleep(ctx, assignmentRecheck) {
			return
		}
	}
}

func (a *Audit) startCollectors(ctx context.Context, running *sync.WaitGroup) {
	for sourceID, plan := range a.registry.Assigned() {
		a.mu.Lock()
		_, started := a.collectors[sourceID]
		a.mu.Unlock()
		if started {
			continue
		}
		item := sources.NewCollector(plan.Setting, plan.Source, sourceID, a.events, a.verifier, a.logger)
		if item == nil {
			continue
		}
		a.mu.Lock()
		a.collectors[sourceID] = item
		a.mu.Unlock()
		if err := a.registry.SaveAssignments(a.events); err != nil {
			a.logger.Warn("source assignments not saved", "reason", "queue")
		}
		running.Go(func() { item.Run(ctx) })
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
	for _, item := range a.collectors {
		reports = append(reports, item.Health())
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
