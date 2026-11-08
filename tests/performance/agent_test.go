//go:build performance

package performance_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"dataguard/internal/agent/collector"
	"dataguard/internal/agent/config"
	"dataguard/internal/agent/queue"
	"dataguard/internal/connector"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/safelog"
	"dataguard/internal/query/frontend/postgres"
)

// Targets of ROADMAP.md, stage 0: the agent keeps up with a busy database on one
// core, and its queue outlasts a center outage of hours at the reference rate.
const (
	agentTarget     = 1_000 // events per second on one core
	autonomyTarget  = 3 * time.Hour
	referenceRate   = 40 // events per second, the average of the reference load
	agentStatements = 50_000
	agentSessions   = 64
	// Applications send prepared statements, so pgAudit logs the same text with
	// parameters. The rest are ad hoc queries with literals, each one new.
	repeatedShare = 0.9
	pgTimeLayout  = "2006-01-02 15:04:05.000 MST"
)

var preparedStatements = []string{
	`SELECT id, email, full_name FROM customers WHERE id = $1`,
	`SELECT phone, address FROM customers WHERE email = $1`,
	`SELECT c.email, o.total, o.status FROM customers c JOIN orders o ON o.customer_id = c.id WHERE o.id = $1`,
	`SELECT id, total, status FROM orders WHERE customer_id = $1 ORDER BY created_at DESC LIMIT 20`,
	`SELECT count(*) FROM orders WHERE status = $1`,
	`UPDATE orders SET status = $1 WHERE id = $2`,
	`UPDATE customers SET phone = $1, address = $2 WHERE id = $3`,
	`INSERT INTO orders (customer_id, total, status, created_at) VALUES ($1, $2, $3, now())`,
	`INSERT INTO payments (order_id, card_number, amount, paid_at) VALUES ($1, $2, $3, now())`,
	`SELECT p.amount, p.paid_at FROM payments p WHERE p.order_id = $1`,
	`DELETE FROM sessions WHERE expires_at < $1`,
	`SELECT customer_id FROM sessions WHERE token = $1 AND expires_at > now()`,
}

var adHocStatements = []string{
	`SELECT id, email, phone FROM customers WHERE full_name LIKE 'Иван%%' AND id > %d`,
	`SELECT c.full_name, sum(o.total) FROM customers c JOIN orders o ON o.customer_id = c.id WHERE o.created_at > now() - interval '%d days' GROUP BY c.full_name`,
	`SELECT * FROM payments WHERE amount > %d ORDER BY paid_at DESC LIMIT 100`,
	`UPDATE orders SET status = 'cancelled' WHERE id = %d`,
}

type agentCatalog struct{}

func (agentCatalog) LogLocation(context.Context) (*time.Location, error) { return time.UTC, nil }

func (agentCatalog) Tables(context.Context) ([]connector.Table, error) {
	table := func(name string, columns ...string) connector.Table {
		result := connector.Table{Database: "crm", Schema: "public", Name: name, Kind: agentv1.TableKind_TABLE_KIND_TABLE}
		for i, column := range columns {
			result.Columns = append(result.Columns, connector.Column{Name: column, Ordinal: uint32(i + 1)})
		}
		return result
	}
	return []connector.Table{
		table("customers", "id", "email", "phone", "full_name", "birth_date", "address", "created_at"),
		table("orders", "id", "customer_id", "total", "status", "created_at"),
		table("payments", "id", "order_id", "card_number", "amount", "paid_at"),
		table("sessions", "id", "customer_id", "token", "expires_at"),
	}, nil
}

// agentLog is a pgAudit jsonlog as PostgreSQL writes it: sessions interleave,
// and each closes with a disconnection that settles its last statement.
func agentLog(t *testing.T, repeated float64) []byte {
	t.Helper()
	random := rand.New(rand.NewPCG(1, 2))
	var log strings.Builder
	line := func(entry map[string]any) {
		entry["backend_type"] = "client backend"
		entry["timestamp"] = time.Now().UTC().Format(pgTimeLayout)
		entry["user"], entry["dbname"] = "crm_app", "crm"
		encoded, err := json.Marshal(entry)
		if err != nil {
			t.Fatal(err)
		}
		log.Write(encoded)
		log.WriteByte('\n')
	}
	for i := range agentStatements {
		statement := preparedStatements[random.IntN(len(preparedStatements))]
		if random.Float64() >= repeated {
			statement = fmt.Sprintf(adHocStatements[random.IntN(len(adHocStatements))], i)
		}
		session := random.IntN(agentSessions)
		line(map[string]any{
			"session_id": fmt.Sprintf("6720a1b2.%x", session), "vxid": fmt.Sprintf("%d/%d", session+3, i),
			"remote_host": fmt.Sprintf("10.20.0.%d", session%8+10),
			"message": fmt.Sprintf(`AUDIT: SESSION,%d,1,READ,SELECT,,,"%s",<not logged>`,
				i+1, strings.ReplaceAll(statement, `"`, `""`)),
		})
	}
	for session := range agentSessions {
		line(map[string]any{
			"session_id": fmt.Sprintf("6720a1b2.%x", session), "vxid": "",
			"message": "disconnection: session time: 0:00:10.000 user=crm_app database=crm host=10.20.0.10",
		})
	}
	return []byte(log.String())
}

// collect runs one collector on one core over a log and returns its rate and the
// queue it filled.
func collect(t *testing.T, repeated float64) (float64, queue.Stats) {
	t.Helper()
	logs := t.TempDir()
	path := filepath.Join(logs, "postgresql.json")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	content := agentLog(t, repeated)
	events, err := queue.Open(t.TempDir(), 4<<30)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = events.Close() })

	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	ctx, stop := context.WithCancel(t.Context())
	defer stop()
	item := collector.New(collector.Options{
		SourceKey: "crm", SourceID: "0190a8c4-7b1e-7c3d-9f10-2a4b6c8d0e1f",
		Reader: collector.NewPostgresReader(logs), Catalog: agentCatalog{}, Frontend: postgres.Frontend{},
		Schema: "public", Queue: events, PollInterval: 10 * time.Millisecond, Logger: safelog.Discard(),
	})
	go item.Run(ctx)
	// A fresh agent starts at the end of the log, so the records are written once
	// it holds a position.
	for item.Health().GetState() != agentv1.AuditSourceState_AUDIT_SOURCE_STATE_OBSERVING {
		time.Sleep(10 * time.Millisecond)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := file.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	var stats queue.Stats
	for deadline := started.Add(2 * time.Minute); ; time.Sleep(50 * time.Millisecond) {
		if stats, err = events.Stats(); err != nil {
			t.Fatal(err)
		}
		if stats.PendingEvents >= agentStatements || time.Now().After(deadline) {
			break
		}
	}
	elapsed := time.Since(started)
	stop()

	if stats.PendingEvents != agentStatements {
		t.Fatalf("queued %d events, want %d", stats.PendingEvents, agentStatements)
	}
	if health := item.Health(); health.GetState() != agentv1.AuditSourceState_AUDIT_SOURCE_STATE_OBSERVING || health.GetLostEventsTotal() != 0 {
		t.Fatalf("health = %+v", health)
	}
	// Every statement must have been analyzed down to columns, or the rate would
	// measure a shortcut.
	items, err := events.Peek(agentStatements, 1<<40)
	if err != nil {
		t.Fatal(err)
	}
	for _, queued := range items {
		if resolution := queued.Event.GetEvidence().GetObjectResolution(); resolution != agentv1.ObjectResolution_OBJECT_RESOLUTION_RESOLVED {
			t.Fatalf("event %d resolved as %s", queued.Sequence, resolution)
		}
	}
	rate := float64(agentStatements) / elapsed.Seconds()
	t.Logf("%d statements, %.0f%% repeated, in %s on one core: %.0f events/s",
		agentStatements, repeated*100, elapsed.Round(time.Millisecond), rate)
	return rate, stats
}

// TestAgentKeepsUpOnOneCore reads a pgAudit log through the whole collector:
// parsing, analysis against the catalog, the contract check and the encrypted
// queue. The same run measures what an event costs in the queue, which is what
// bounds how long the agent outlasts the center.
func TestAgentKeepsUpOnOneCore(t *testing.T) {
	rate, stats := collect(t, repeatedShare)
	if rate < agentTarget {
		t.Errorf("agent throughput %.0f events/s on one core, target %d", rate, agentTarget)
	}

	perEvent := float64(stats.PendingBytes) / float64(stats.PendingEvents)
	capacity := float64(config.DefaultQueueCapacity) / perEvent
	autonomy := time.Duration(capacity / referenceRate * float64(time.Second))
	t.Logf("queue: %.0f bytes per event, %.0f events in %d MiB: %s at %d events/s, %s at the tenfold peak",
		perEvent, capacity, config.DefaultQueueCapacity>>20, autonomy.Round(time.Minute), referenceRate, (autonomy / 10).Round(time.Minute))
	if autonomy < autonomyTarget {
		t.Errorf("queue lasts %s at %d events/s, target %s", autonomy.Round(time.Minute), referenceRate, autonomyTarget)
	}

	// Without repeats every statement goes through the parser. There is no target
	// for this; CONNECTOR_SPEC.md quotes the number.
	t.Run("all unique", func(t *testing.T) { collect(t, 0) })
}
