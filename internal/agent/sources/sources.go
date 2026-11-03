// Package sources opens the databases named in the agent's local configuration.
// The center refers to them only by id, and an id it invents resolves to nothing.
package sources

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"dataguard/internal/agent/config"
	"dataguard/internal/connector"
	"dataguard/internal/connector/mssql"
	"dataguard/internal/connector/mysql"
	"dataguard/internal/connector/postgres"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

type entry struct {
	key     string
	engine  agentv1.Engine
	source  connector.Scannable
	setting *config.Source
}

// Registry is the set of configured sources and their center-assigned ids.
type Registry struct {
	entries []*entry

	mu   sync.RWMutex
	byID map[string]*entry
}

// Open connects to every configured source. Connections are lazy, so an
// unreachable database does not stop the agent; it shows up in Probe instead.
func Open(settings []config.Source) (*Registry, error) {
	registry := &Registry{byID: map[string]*entry{}}
	for i := range settings {
		opened, err := open(&settings[i])
		if err != nil {
			return nil, errors.Join(err, registry.Close())
		}
		registry.entries = append(registry.entries, opened)
	}
	return registry, nil
}

func open(setting *config.Source) (*entry, error) {
	password, err := setting.Password()
	if err != nil {
		return nil, err
	}
	credentials := connector.Credentials{
		Host: setting.Host, Port: setting.Port, Database: setting.Database,
		Username: setting.Username, Password: password, TLS: connector.TLSMode(setting.TLS),
	}
	opened := &entry{key: setting.Key, setting: setting}
	switch setting.Engine {
	case config.EnginePostgreSQL:
		opened.engine = agentv1.Engine_ENGINE_POSTGRESQL
		opened.source, err = postgres.Open(credentials, setting.MaxConnections)
	case config.EngineMySQL:
		opened.engine = agentv1.Engine_ENGINE_MYSQL
		opened.source, err = mysql.Open(credentials, mysql.FlavorMySQL, setting.MaxConnections)
	case config.EngineMariaDB:
		opened.engine = agentv1.Engine_ENGINE_MARIADB
		opened.source, err = mysql.Open(credentials, mysql.FlavorMariaDB, setting.MaxConnections)
	case config.EngineMSSQL:
		opened.engine = agentv1.Engine_ENGINE_MSSQL
		opened.source, err = mssql.Open(credentials, setting.Audit.Directory, setting.MaxConnections)
	default:
		err = fmt.Errorf("source %s: unknown engine", setting.Key)
	}
	if err != nil {
		return nil, err
	}
	return opened, nil
}

// Close releases all connections.
func (r *Registry) Close() error {
	var failures []error
	for _, item := range r.entries {
		failures = append(failures, item.source.Close())
	}
	return errors.Join(failures...)
}

// Probe reports the current state of each source.
func (r *Registry) Probe(ctx context.Context) []*agentv1.SourceReport {
	reports := make([]*agentv1.SourceReport, 0, len(r.entries))
	for _, item := range r.entries {
		version, capabilities := item.source.Probe(ctx)
		reports = append(reports, &agentv1.SourceReport{
			SourceKey: item.key, Engine: item.engine, EngineVersion: version, Capabilities: capabilities,
		})
	}
	return reports
}

// Assign records the ids chosen by the center.
func (r *Registry) Assign(assignments []*agentv1.SourceAssignment) {
	byKey := make(map[string]*entry, len(r.entries))
	for _, item := range r.entries {
		byKey[item.key] = item
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, assignment := range assignments {
		if item, ok := byKey[assignment.GetSourceKey()]; ok {
			r.byID[assignment.GetSourceId()] = item
		}
	}
}

// ByID resolves a center-assigned id to a configured source.
func (r *Registry) ByID(sourceID string) (connector.Scannable, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	item, ok := r.byID[sourceID]
	if !ok {
		return nil, false
	}
	return item.source, true
}
