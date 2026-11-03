// Package sources holds the databases this agent serves. The runtime fills it
// from the center's signed list after checking each target against the local
// allowlist and opening its sealed password. An id the center did not assign
// resolves to nothing.
package sources

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"dataguard/internal/connector"
	"dataguard/internal/connector/mssql"
	"dataguard/internal/connector/mysql"
	"dataguard/internal/connector/postgres"
	"dataguard/internal/contract/codes"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

// Engine names, the same as in the API and in sealed-password bindings.
const (
	EnginePostgreSQL = "postgresql"
	EngineMySQL      = "mysql"
	EngineMariaDB    = "mariadb"
	EngineMSSQL      = "mssql"
)

// Engines maps contract engines to their names.
var Engines = map[agentv1.Engine]string{
	agentv1.Engine_ENGINE_POSTGRESQL: EnginePostgreSQL,
	agentv1.Engine_ENGINE_MYSQL:      EngineMySQL,
	agentv1.Engine_ENGINE_MARIADB:    EngineMariaDB,
	agentv1.Engine_ENGINE_MSSQL:      EngineMSSQL,
}

// Definition is a source the agent agreed to open, with its opened password.
type Definition struct {
	ID             string
	Name           string
	Engine         string
	Host           string
	Port           int
	Database       string
	Username       string
	Password       string
	TLS            string
	MaxConnections int
	AuditDirectory string
}

// Refusal is a source from the center the agent will not open. Code says why
// and is reported back, for example TARGET_NOT_ALLOWED.
type Refusal struct {
	ID     string
	Engine agentv1.Engine
	Code   string
}

type entry struct {
	definition Definition
	engine     agentv1.Engine
	source     connector.Scannable
	revision   uint64
	// users counts scans and collectors holding source; a replaced entry is
	// closed when the last of them releases it.
	users   int
	retired bool
}

// Registry is the current set of sources. It is safe for concurrent use.
type Registry struct {
	// applying serializes Apply, which opens connectors outside mu.
	applying sync.Mutex
	mu       sync.Mutex
	entries  map[string]*entry
	refused  map[string]Refusal
	revision uint64
}

// NewRegistry creates an empty registry.
func NewRegistry() *Registry {
	return &Registry{entries: map[string]*entry{}, refused: map[string]Refusal{}}
}

// Apply replaces the set of sources. An unchanged source keeps its
// connections; a changed one gets a new revision and new connections.
func (r *Registry) Apply(definitions []Definition, refusals []Refusal) error {
	r.applying.Lock()
	defer r.applying.Unlock()
	opened := make(map[string]*entry, len(definitions))
	refusals = append([]Refusal{}, refusals...)
	var failures []error
	r.mu.Lock()
	current := r.entries
	r.mu.Unlock()
	for _, definition := range definitions {
		if existing, ok := current[definition.ID]; ok && existing.definition == definition {
			opened[definition.ID] = existing
			continue
		}
		item, err := open(definition)
		if err != nil {
			failures = append(failures, err)
			refusals = append(refusals, Refusal{ID: definition.ID, Code: codes.OpenFailed})
			continue
		}
		opened[definition.ID] = item
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for _, item := range opened {
		if item.revision == 0 {
			r.revision++
			item.revision = r.revision
		}
	}
	for id, item := range r.entries {
		if opened[id] != item {
			r.retire(item)
		}
	}
	r.entries = opened
	r.refused = make(map[string]Refusal, len(refusals))
	for _, refusal := range refusals {
		r.refused[refusal.ID] = refusal
	}
	return errors.Join(failures...)
}

// RefusalCodes returns the code of each source the agent did not open.
func (r *Registry) RefusalCodes() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	codes := make(map[string]string, len(r.refused))
	for id, refusal := range r.refused {
		codes[id] = refusal.Code
	}
	return codes
}

func (r *Registry) retire(item *entry) {
	item.retired = true
	if item.users == 0 {
		_ = item.source.Close()
	}
}

func open(definition Definition) (*entry, error) {
	credentials := connector.Credentials{
		Host: definition.Host, Port: definition.Port, Database: definition.Database,
		Username: definition.Username, Password: definition.Password, TLS: connector.TLSMode(definition.TLS),
	}
	item := &entry{definition: definition}
	var err error
	switch definition.Engine {
	case EnginePostgreSQL:
		item.engine = agentv1.Engine_ENGINE_POSTGRESQL
		item.source, err = postgres.Open(credentials, definition.MaxConnections)
	case EngineMySQL:
		item.engine = agentv1.Engine_ENGINE_MYSQL
		item.source, err = mysql.Open(credentials, mysql.FlavorMySQL, definition.MaxConnections)
	case EngineMariaDB:
		item.engine = agentv1.Engine_ENGINE_MARIADB
		item.source, err = mysql.Open(credentials, mysql.FlavorMariaDB, definition.MaxConnections)
	case EngineMSSQL:
		item.engine = agentv1.Engine_ENGINE_MSSQL
		item.source, err = mssql.Open(credentials, definition.AuditDirectory, definition.MaxConnections)
	default:
		err = errors.New("unknown engine")
	}
	if err != nil {
		return nil, fmt.Errorf("open source %s: %w", definition.ID, err)
	}
	return item, nil
}

// Acquire returns a source for use until release is called. A source replaced
// or removed meanwhile stays open until then.
func (r *Registry) Acquire(sourceID string) (source connector.Scannable, release func(), ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	item, ok := r.entries[sourceID]
	if !ok {
		return nil, nil, false
	}
	item.users++
	var once sync.Once
	return item.source, func() { once.Do(func() { r.release(item) }) }, true
}

func (r *Registry) release(item *entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	item.users--
	if item.retired && item.users == 0 {
		_ = item.source.Close()
	}
}

// Plan is one open source as the audit runtime sees it. A new Revision means
// the definition changed and its collector must restart.
type Plan struct {
	Definition Definition
	Revision   uint64
}

// Plans returns the open sources.
func (r *Registry) Plans() map[string]Plan {
	r.mu.Lock()
	defer r.mu.Unlock()
	plans := make(map[string]Plan, len(r.entries))
	for id, item := range r.entries {
		plans[id] = Plan{Definition: item.definition, Revision: item.revision}
	}
	return plans
}

// Probe reports every source from the center: what an open one can do, and
// why a refused one was not opened.
func (r *Registry) Probe(ctx context.Context) []*agentv1.SourceReport {
	r.mu.Lock()
	ids := make([]string, 0, len(r.entries))
	for id := range r.entries {
		ids = append(ids, id)
	}
	reports := make([]*agentv1.SourceReport, 0, len(r.entries)+len(r.refused))
	for _, refusal := range r.refused {
		reports = append(reports, &agentv1.SourceReport{SourceId: refusal.ID, Engine: refusal.Engine, StatusCode: refusal.Code})
	}
	r.mu.Unlock()
	for _, id := range ids {
		source, release, ok := r.Acquire(id)
		if !ok {
			continue
		}
		version, capabilities := source.Probe(ctx)
		release()
		report := &agentv1.SourceReport{SourceId: id, Engine: r.engineOf(id), EngineVersion: version, Capabilities: capabilities}
		if version == "" {
			// The probe could not even read the version: no connection or no login.
			report.StatusCode = codes.ConnectionFailed
		}
		reports = append(reports, report)
	}
	return reports
}

func (r *Registry) engineOf(sourceID string) agentv1.Engine {
	r.mu.Lock()
	defer r.mu.Unlock()
	if item, ok := r.entries[sourceID]; ok {
		return item.engine
	}
	return agentv1.Engine_ENGINE_UNSPECIFIED
}

// Close releases all connections.
func (r *Registry) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var failures []error
	for _, item := range r.entries {
		failures = append(failures, item.source.Close())
	}
	r.entries = map[string]*entry{}
	return errors.Join(failures...)
}
