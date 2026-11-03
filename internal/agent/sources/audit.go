package sources

import (
	"encoding/json"
	"errors"
	"log/slog"

	"dataguard/internal/agent/collector"
	"dataguard/internal/agent/config"
	"dataguard/internal/agent/queue"
	"dataguard/internal/connector"
	mysqlfrontend "dataguard/internal/query/frontend/mysql"
	pgfrontend "dataguard/internal/query/frontend/postgres"
	"dataguard/internal/query/frontend/tsql"
)

const assignmentsMeta = "source_assignments"

// NewCollector builds the collector matching a source's engine. It returns nil
// when no audit directory is configured; the capability report states the rest.
func NewCollector(setting *config.Source, source connector.Scannable, sourceID string, events *queue.Queue, verifier collector.Verifier, logger *slog.Logger) *collector.Collector {
	if setting.Audit.Directory == "" {
		return nil
	}
	options := collector.Options{
		SourceKey: setting.Key, SourceID: sourceID, Catalog: source, Queue: events,
		Verifier: verifier, Logger: logger,
	}
	switch setting.Engine {
	case config.EnginePostgreSQL:
		options.Reader = collector.NewPostgresReader(setting.Audit.Directory)
		options.Frontend, options.Schema = pgfrontend.Frontend{}, "public"
	case config.EngineMySQL:
		options.Reader = collector.NewMySQLReader(setting.Audit.Directory)
		options.Frontend, options.Schema, options.FoldCase = mysqlfrontend.Frontend{}, setting.Database, true
	case config.EngineMariaDB:
		options.Reader = collector.NewMariaDBReader(setting.Audit.Directory)
		options.Frontend, options.Schema, options.FoldCase = mysqlfrontend.Frontend{}, setting.Database, true
	case config.EngineMSSQL:
		logSource, ok := source.(connector.AuditLogSource)
		if !ok {
			return nil
		}
		options.Reader = collector.NewSQLServerReader(logSource, setting.Audit.Directory)
		options.Frontend, options.Schema, options.FoldCase = tsql.Frontend{}, "dbo", true
	default:
		return nil
	}
	return collector.New(options)
}

// Plan is what the audit runtime needs for one source.
type Plan struct {
	Setting *config.Source
	Source  connector.Scannable
}

// Assigned returns sources with a known id. The assignment is persisted, because
// after a restart the center may be down and auditing must not wait for it.
func (r *Registry) Assigned() map[string]Plan {
	r.mu.RLock()
	defer r.mu.RUnlock()
	plans := make(map[string]Plan, len(r.byID))
	for id, item := range r.byID {
		plans[id] = Plan{Setting: item.setting, Source: item.source}
	}
	return plans
}

// SaveAssignments persists the current mapping of ids to keys.
func (r *Registry) SaveAssignments(events *queue.Queue) error {
	r.mu.RLock()
	stored := make(map[string]string, len(r.byID))
	for id, item := range r.byID {
		stored[item.key] = id
	}
	r.mu.RUnlock()
	encoded, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	return events.SetMeta(assignmentsMeta, encoded)
}

// LoadAssignments restores a mapping saved earlier.
func (r *Registry) LoadAssignments(events *queue.Queue) error {
	encoded, err := events.Meta(assignmentsMeta)
	if err != nil || encoded == nil {
		return err
	}
	var stored map[string]string
	if err := json.Unmarshal(encoded, &stored); err != nil {
		return errors.Join(errors.New("decode source assignments"), err)
	}
	byKey := make(map[string]*entry, len(r.entries))
	for _, item := range r.entries {
		byKey[item.key] = item
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, id := range stored {
		if item, ok := byKey[key]; ok {
			r.byID[id] = item
		}
	}
	return nil
}
