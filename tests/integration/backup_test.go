//go:build integration

package integration_test

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"dataguard/internal/agent/center"
	"dataguard/internal/agent/runtime"
	"dataguard/internal/core/fleet"
	"dataguard/internal/core/oplog"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/safelog"
	"dataguard/internal/server/storage/clickhouse"
	"dataguard/internal/server/storage/postgres"
)

// centerPostgres runs the backup tools of the stand's central database; the
// image has them, the host may not.
const centerPostgres = "dataguard-dev-center-postgres-1"

func postgresTool(t *testing.T, stdin []byte, arguments ...string) []byte {
	t.Helper()
	command := exec.CommandContext(t.Context(), "docker", append([]string{"exec", "-i", centerPostgres}, arguments...)...)
	command.Stdin = bytes.NewReader(stdin)
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		t.Fatalf("%s: %v\n%s", arguments[0], err, stderr.String())
	}
	return output
}

func databaseOf(t *testing.T, dsn string) (*url.URL, string) {
	t.Helper()
	parsed, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	return parsed, strings.TrimPrefix(parsed.Path, "/")
}

// appliedSources keeps the last list the agent accepted.
type appliedSources struct {
	mu   sync.Mutex
	list *agentv1.SourceList
}

func (a *appliedSources) ApplySources(_ context.Context, list *agentv1.SourceList) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.list = list
}

func (a *appliedSources) names() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var names []string
	for _, source := range a.list.GetSources() {
		names = append(names, source.GetName())
	}
	return names
}

// runAgent drives an agent's control loop against one server until the test ends.
func runAgent(t *testing.T, agent enrolledAgent, serverURL, caFile string, sources *appliedSources) {
	t.Helper()
	client, err := center.New(serverURL, caFile, agent.store, agent.metrics)
	if err != nil {
		t.Fatal(err)
	}
	control := runtime.NewControl(runtime.Options{
		Client: client, Identity: agent.store, Prober: noSources{}, Sources: sources, Version: "test",
		HeartbeatInterval: 100 * time.Millisecond, Logger: safelog.Discard(), Metrics: agent.metrics,
	})
	ctx, stop := context.WithCancel(t.Context())
	var running sync.WaitGroup
	running.Go(func() { control.Run(ctx) })
	t.Cleanup(func() {
		stop()
		running.Wait()
	})
}

// ROADMAP.md, stage 1: a restore from a backup brings back the registry and the
// sources, and agents that applied newer lists and policies take the restored
// ones instead of refusing them as rollbacks.
func TestRestoreFromBackupBringsBackRegistryAndSources(t *testing.T) {
	ctx := oplog.WithActor(t.Context(), oplog.Actor{Subject: "s-admin", Name: "admin"})
	platform := startPlatform(t)
	created, environment := platform.newTenant(t, "Acme")
	agent := platform.enroll(t, created.ID, environment.ID)
	sealed := sealedFor(t, agent.store.SealingKey().PublicKey().Bytes())
	addSource := func(name string) {
		t.Helper()
		_, err := platform.app.Fleet.CreateSource(ctx, created.ID, fleet.Source{
			AgentID: agent.store.AgentID(), Key: name, Engine: "postgresql", Host: "db.invalid", Port: 5432,
			Database: "crm", Username: "dg_scanner", TLS: "disable", SealedPassword: sealed,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	detector := func(name string) *agentv1.CustomDetector {
		return &agentv1.CustomDetector{CategoryId: "CUSTOM." + name, NamePattern: "(?i)" + strings.ToLower(name)}
	}
	addSource("crm")
	if _, err := platform.app.Policies.Publish(ctx, created.ID, "admin", []*agentv1.CustomDetector{detector("CONTRACT")}, nil); err != nil {
		t.Fatal(err)
	}
	sources := &appliedSources{}
	runAgent(t, agent, platform.agents.URL, platform.caFile, sources)
	waitFor(t, "the agent applies the first state", func() bool { return agent.store.PolicyVersion() == 1 && len(sources.names()) == 1 })

	// The backup: the database as its owner, and the PKI directory.
	_, database := databaseOf(t, platform.ownerDSN)
	dump := postgresTool(t, nil, "pg_dump", "--format=custom", "--username=dg_owner", "--dbname="+database)
	pkiCopy := t.TempDir()
	if err := os.CopyFS(pkiCopy, os.DirFS(platform.pkiDir)); err != nil {
		t.Fatal(err)
	}

	addSource("billing")
	if _, err := platform.app.Policies.Publish(ctx, created.ID, "admin", []*agentv1.CustomDetector{detector("CONTRACT"), detector("INVOICE")}, nil); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the agent applies changes made after the backup", func() bool { return agent.store.PolicyVersion() == 2 && len(sources.names()) == 2 })
	appliedSourcesVersion := agent.store.SourcesVersion()

	// The restore, into a new database next to the old one.
	restoredName := database + "_restored"
	owner, err := pgx.Connect(t.Context(), platform.ownerDSN)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := owner.Exec(t.Context(), fmt.Sprintf(`CREATE DATABASE %s`, pgx.Identifier{restoredName}.Sanitize())); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup := context.WithoutCancel(t.Context())
		_, _ = owner.Exec(cleanup, fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, pgx.Identifier{restoredName}.Sanitize()))
		_ = owner.Close(cleanup)
	})
	postgresTool(t, dump, "pg_restore", "--username=dg_owner", "--dbname="+restoredName, "--exit-on-error")
	runtimeURL, _ := databaseOf(t, platform.runtimeDSN)
	runtimeURL.Path = "/" + restoredName
	store, err := postgres.Open(t.Context(), runtimeURL.String())
	if err != nil {
		t.Fatalf("open the restored database as the server: %v", err)
	}
	t.Cleanup(store.Close)
	events, err := clickhouse.Open(t.Context(), platform.eventSettings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = events.Close() })
	restored := serve(t, store, events, pkiCopy, platform.authn, platform.broker)

	// The agent finds the restored center; it already holds newer versions.
	sources = &appliedSources{}
	runAgent(t, agent, restored.agents.URL, platform.caFile, sources)
	waitFor(t, "the agent takes the restored list and policy", func() bool {
		return agent.store.SourcesVersion() > appliedSourcesVersion && agent.store.PolicyVersion() > 2
	})
	if names := sources.names(); len(names) != 1 || names[0] != "crm" {
		t.Fatalf("the agent serves %v, want the restored crm only", names)
	}
	policy, err := agent.store.LoadPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if detectors := policy.GetCustomDetectors(); len(detectors) != 1 || detectors[0].GetCategoryId() != "CUSTOM.CONTRACT" {
		t.Fatalf("the agent runs %v, want the policy of the backup", detectors)
	}

	listed, err := restored.app.Fleet.ListSources(t.Context(), created.ID)
	if err != nil || len(listed) != 1 || listed[0].Key != "crm" {
		t.Fatalf("restored registry: %+v, %v", listed, err)
	}
	if _, err := restored.app.Fleet.GetAgent(t.Context(), created.ID, agent.store.AgentID()); err != nil {
		t.Fatalf("the agent is not in the restored registry: %v", err)
	}
	journal, err := restored.app.Journal.List(t.Context(), created.ID, oplog.Query{Limit: 1})
	if err != nil || len(journal) != 1 || journal[0].Details[oplog.DetailReason] != oplog.ReasonRestore || journal[0].Actor.Subject != "" {
		t.Fatalf("the journal does not say the platform published the restored policy: %+v, %v", journal, err)
	}
}
