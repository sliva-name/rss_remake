//go:build integration

package integration_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"

	"dataguard/internal/agent/collector"
	"dataguard/internal/agent/config"
	"dataguard/internal/agent/queue"
	"dataguard/internal/agent/runtime"
	"dataguard/internal/agent/sources"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/safelog"
	"dataguard/internal/testkit/seed"
	"dataguard/internal/testkit/stand"
	"dataguard/internal/testkit/synthetic"
	"dataguard/sdk/go/appcontext"
)

const auditWait = 20 * time.Second

type auditHarness struct {
	source   stand.Source
	events   *queue.Queue
	sourceID string
	cancel   context.CancelFunc
	done     chan struct{}
	item     *collector.Collector
	stateDir string
	registry *sources.Registry
	verifier collector.Verifier
}

func startCollector(t *testing.T, source stand.Source, stateDir string, verifier collector.Verifier) *auditHarness {
	t.Helper()
	source.Config.Audit.Directory = stand.AuditDirectory(source.Dialect.Name)
	events, err := queue.Open(stateDir, 1<<24)
	if err != nil {
		t.Fatalf("queue: %v", err)
	}
	registry, err := sources.Open([]config.Source{source.Config})
	if err != nil {
		t.Fatalf("sources: %v", err)
	}
	sourceID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(stateDir)).String()
	registry.Assign([]*agentv1.SourceAssignment{{SourceKey: source.Config.Key, SourceId: sourceID}})
	plans := registry.Assigned()
	item := sources.NewCollector(plans[sourceID].Setting, plans[sourceID].Source, sourceID, events, verifier, safelog.Discard())
	if item == nil {
		t.Fatal("no collector")
	}
	ctx, cancel := context.WithCancel(context.Background())
	harness := &auditHarness{
		source: source, events: events, sourceID: sourceID, cancel: cancel, done: make(chan struct{}),
		item: item, stateDir: stateDir, registry: registry, verifier: verifier,
	}
	go func() {
		defer close(harness.done)
		item.Run(ctx)
	}()
	t.Cleanup(harness.stop)
	harness.awaitObserving(t)
	return harness
}

func (h *auditHarness) stop() {
	if h.cancel == nil {
		return
	}
	h.cancel()
	<-h.done
	h.cancel = nil
	_ = h.events.Close()
	_ = h.registry.Close()
}

func (h *auditHarness) awaitObserving(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(auditWait)
	for time.Now().Before(deadline) {
		if h.item.Health().GetState() == agentv1.AuditSourceState_AUDIT_SOURCE_STATE_OBSERVING {
			cursor, err := h.events.Cursor(h.source.Config.Key)
			if err == nil && cursor != nil {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("collector never observed the source: %+v", h.item.Health())
}

func (h *auditHarness) all(t *testing.T) []*agentv1.AuditEvent {
	t.Helper()
	items, err := h.events.Peek(100_000, 1<<30)
	if err != nil {
		t.Fatalf("Peek: %v", err)
	}
	events := make([]*agentv1.AuditEvent, 0, len(items))
	for _, item := range items {
		events = append(events, item.Event)
	}
	return events
}

// waitFor polls until match finds an event among all stored ones.
func (h *auditHarness) waitFor(t *testing.T, what string, match func(*agentv1.AuditEvent) bool) *agentv1.AuditEvent {
	t.Helper()
	deadline := time.Now().Add(auditWait)
	for time.Now().Before(deadline) {
		for _, event := range h.all(t) {
			if match(event) {
				return event
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	var seen []string
	for _, event := range h.all(t) {
		seen = append(seen, event.GetEventType().String()+"/"+event.GetOperation().GetType().String())
	}
	t.Fatalf("no event: %s; saw %v", what, seen)
	return nil
}

func readsColumn(event *agentv1.AuditEvent, table, column string) bool {
	return slices.ContainsFunc(event.GetOperation().GetColumns(), func(item *agentv1.AccessedColumn) bool {
		return item.GetRead() && item.GetColumn().GetColumn() == column && item.GetColumn().GetTable().GetTable() == table
	})
}

func TestAuditOnEveryEngine(t *testing.T) {
	for _, source := range stand.AllSources(t) {
		t.Run(source.Dialect.Name, func(t *testing.T) {
			ctx := context.Background()
			if err := seed.Tables(ctx, source.Admin, source.Dialect, 5, synthetic.New(3)); err != nil {
				t.Fatalf("seed: %v", err)
			}
			// The MySQL general log names the user only at login, so the test connects
			// after the collector starts. Older sessions stay unidentified on purpose.
			source.Admin.SetMaxIdleConns(0)
			harness := startCollector(t, source, t.TempDir(), nil)

			literal := synthetic.CanaryMarker + ".literal@example.invalid"
			statement := fmt.Sprintf(`SELECT u.email, o.note FROM %s u JOIN %s o ON o.id = u.id WHERE u.email = '%s'`,
				seed.Users, seed.Orders, literal)
			if _, err := source.Admin.ExecContext(ctx, statement); err != nil {
				t.Fatalf("query: %v", err)
			}
			update := fmt.Sprintf(`UPDATE %s SET status = 'blocked' WHERE id = 1`, seed.Users)
			if _, err := source.Admin.ExecContext(ctx, update); err != nil {
				t.Fatalf("update: %v", err)
			}
			if _, err := source.Admin.ExecContext(ctx, `SELECT no_such_column FROM `+seed.Users); err == nil {
				t.Fatal("expected a failing statement")
			}
			if _, err := source.Admin.ExecContext(ctx, `SELECT email FROM `+seed.Users); err != nil {
				t.Fatalf("follow-up: %v", err)
			}

			read := harness.waitFor(t, "resolved join", func(event *agentv1.AuditEvent) bool {
				return readsColumn(event, seed.Users, "email") && readsColumn(event, seed.Orders, "note")
			})
			if read.GetEventType() != agentv1.EventType_EVENT_TYPE_DATA_ACCESS {
				t.Errorf("event type = %s", read.GetEventType())
			}
			// SQL Server writes one row per table: a join must still be one access.
			sameQuery, identifiers := 0, map[string]bool{}
			for _, event := range harness.all(t) {
				if identifiers[event.GetEventId()] {
					t.Errorf("duplicate event %s", event.GetEventId())
				}
				identifiers[event.GetEventId()] = true
				if event.GetOperation().GetQueryFingerprint() == read.GetOperation().GetQueryFingerprint() {
					sameQuery++
				}
			}
			if sameQuery != 1 {
				t.Errorf("one join produced %d events", sameQuery)
			}
			if read.GetEvidence().GetObjectResolution() != agentv1.ObjectResolution_OBJECT_RESOLUTION_RESOLVED {
				t.Errorf("resolution = %s", read.GetEvidence().GetObjectResolution())
			}
			if read.GetActor().GetDatabasePrincipal() != "dg_app" {
				t.Errorf("principal = %q", read.GetActor().GetDatabasePrincipal())
			}
			if read.GetActor().GetIdentityConfidence() != agentv1.IdentityConfidence_IDENTITY_CONFIDENCE_DB_PRINCIPAL_ONLY {
				t.Errorf("identity = %s", read.GetActor().GetIdentityConfidence())
			}
			if !strings.HasPrefix(read.GetOperation().GetQueryFingerprint(), "sha256:") {
				t.Errorf("fingerprint = %q", read.GetOperation().GetQueryFingerprint())
			}
			if source.Dialect.Name == "mysql" {
				if got := read.GetEvidence().GetLevel(); got != agentv1.EvidenceLevel_EVIDENCE_LEVEL_REFERENCED {
					t.Errorf("the general log proves no execution, level = %s", got)
				}
			} else if got := read.GetEvidence().GetLevel(); got != agentv1.EvidenceLevel_EVIDENCE_LEVEL_EXECUTED {
				t.Errorf("level = %s", got)
			}

			modification := harness.waitFor(t, "update", func(event *agentv1.AuditEvent) bool {
				return event.GetEventType() == agentv1.EventType_EVENT_TYPE_DATA_MODIFICATION
			})
			written := slices.ContainsFunc(modification.GetOperation().GetColumns(), func(item *agentv1.AccessedColumn) bool {
				return item.GetWritten() && item.GetColumn().GetColumn() == "status"
			})
			if !written {
				t.Errorf("update columns = %v", modification.GetOperation().GetColumns())
			}

			// SQL Server rejects an unknown column while binding, before auditing, and
			// the MySQL general log records no outcome. Neither can report this failure.
			if source.Dialect.Name == "postgresql" || source.Dialect.Name == "mariadb" {
				harness.waitFor(t, "failed statement", func(event *agentv1.AuditEvent) bool {
					return event.GetEventType() == agentv1.EventType_EVENT_TYPE_FAILED_ACCESS &&
						event.GetExecution().GetErrorCode() != ""
				})
			}
			harness.assertNoMarker(t)
		})
	}
}

func (h *auditHarness) assertNoMarker(t *testing.T) {
	t.Helper()
	for _, event := range h.all(t) {
		encoded, err := protojson.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), synthetic.CanaryMarker) {
			t.Fatalf("event carries a value: %s", encoded)
		}
	}
}

func TestReplayAfterRestartKeepsEveryEventAndAddsNone(t *testing.T) {
	ctx := context.Background()
	source := stand.PostgresSource(t)
	if err := seed.Tables(ctx, source.Admin, source.Dialect, 3, synthetic.New(3)); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	harness := startCollector(t, source, stateDir, nil)
	run := func(count int, table string) {
		t.Helper()
		for range count {
			if _, err := source.Admin.ExecContext(ctx, `SELECT email FROM `+table); err != nil {
				t.Fatal(err)
			}
		}
	}
	reads := func(events []*agentv1.AuditEvent) (total, unique int) {
		seen := map[string]bool{}
		for _, event := range events {
			if readsColumn(event, seed.Users, "email") {
				total++
				seen[event.GetEventId()] = true
			}
		}
		return total, len(seen)
	}
	run(5, seed.Users)
	harness.waitFor(t, "first batch", func(*agentv1.AuditEvent) bool {
		total, _ := reads(harness.all(t))
		return total >= 4
	})
	harness.stop()

	run(5, seed.Users)
	restarted := startCollector(t, source, stateDir, nil)
	run(1, seed.Users)
	restarted.waitFor(t, "events written while stopped", func(*agentv1.AuditEvent) bool {
		_, unique := reads(restarted.all(t))
		return unique >= 10
	})
	if total, unique := reads(restarted.all(t)); unique < 10 || total < unique {
		t.Fatalf("total %d, unique %d", total, unique)
	}
}

func TestUnparsableStatementLeavesNoTraceOfItsText(t *testing.T) {
	ctx := context.Background()
	source := stand.MariaDBSource(t)
	harness := startCollector(t, source, t.TempDir(), nil)

	statement := fmt.Sprintf(`SELECT '%s' FRM nothing`, synthetic.CanaryMarker)
	if _, err := source.Admin.ExecContext(ctx, statement); err == nil {
		t.Fatal("expected a syntax error")
	}
	event := harness.waitFor(t, "unresolved", func(event *agentv1.AuditEvent) bool {
		return event.GetEvidence().GetObjectResolution() == agentv1.ObjectResolution_OBJECT_RESOLUTION_UNRESOLVED
	})
	if event.GetOperation().GetQueryFingerprint() != "" {
		t.Fatal("an unparsed statement must have no fingerprint")
	}
	harness.assertNoMarker(t)
}

func TestApplicationContext(t *testing.T) {
	ctx := context.Background()
	source := stand.PostgresSource(t)
	if err := seed.Tables(ctx, source.Admin, source.Dialect, 3, synthetic.New(3)); err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := verifierFor(t, map[string]ed25519.PublicKey{"crm": public})
	harness := startCollector(t, source, t.TempDir(), verifier)
	_, foreignKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inTransaction := func(signer *appcontext.Signer, subject, table string) {
		t.Helper()
		token, err := signer.Token(subject, "dg_app", "trace1")
		if err != nil {
			t.Fatal(err)
		}
		tx, err := source.Admin.BeginTx(ctx, &sql.TxOptions{})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if err := appcontext.Apply(ctx, tx, token); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, `SELECT email FROM `+table); err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
	}

	inTransaction(appcontext.NewSigner("crm", private), "employee-123", seed.Users)
	verified := harness.waitFor(t, "verified", func(event *agentv1.AuditEvent) bool {
		return event.GetActor().GetIdentityConfidence() == agentv1.IdentityConfidence_IDENTITY_CONFIDENCE_VERIFIED
	})
	if verified.GetActor().GetApplicationPrincipal() != "employee-123" || verified.GetActor().GetApplicationId() != "crm" ||
		verified.GetCorrelation().GetTraceId() != "trace1" {
		t.Fatalf("actor = %+v", verified.GetActor())
	}

	inTransaction(appcontext.NewSigner("crm", foreignKey), "employee-999", seed.Users)
	claim := harness.waitFor(t, "forged context", func(event *agentv1.AuditEvent) bool {
		return event.GetActor().GetIdentityConfidence() == agentv1.IdentityConfidence_IDENTITY_CONFIDENCE_UNVERIFIED_CLAIM
	})
	if claim.GetActor().GetApplicationPrincipal() != "" {
		t.Fatalf("a forged subject must not reach the event: %+v", claim.GetActor())
	}
	for _, event := range harness.all(t) {
		if event.GetActor().GetApplicationPrincipal() == "employee-999" {
			t.Fatal("forged subject stored")
		}
	}

	// A context ends with its transaction, even on a pooled connection.
	if _, err := source.Admin.ExecContext(ctx, `SELECT status FROM `+seed.Users); err != nil {
		t.Fatal(err)
	}
	plain := harness.waitFor(t, "no context", func(event *agentv1.AuditEvent) bool {
		return readsColumn(event, seed.Users, "status")
	})
	if plain.GetActor().GetIdentityConfidence() != agentv1.IdentityConfidence_IDENTITY_CONFIDENCE_DB_PRINCIPAL_ONLY {
		t.Fatalf("context leaked to the next statement: %+v", plain.GetActor())
	}
}

func verifierFor(t *testing.T, keys map[string]ed25519.PublicKey) *runtime.ContextVerifier {
	t.Helper()
	var applications []config.Application
	for id, key := range keys {
		path := filepath.Join(t.TempDir(), "key")
		encoded := []byte(base64.StdEncoding.EncodeToString(key))
		if err := os.WriteFile(path, encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		applications = append(applications, config.Application{ID: id, PublicKeyFile: path})
	}
	verifier, err := runtime.NewContextVerifier(applications)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}
