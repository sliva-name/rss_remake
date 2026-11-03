package sources

import (
	"log/slog"

	"dataguard/internal/agent/collector"
	"dataguard/internal/agent/queue"
	"dataguard/internal/agent/telemetry"
	"dataguard/internal/connector"
	mysqlfrontend "dataguard/internal/query/frontend/mysql"
	pgfrontend "dataguard/internal/query/frontend/postgres"
	"dataguard/internal/query/frontend/tsql"
)

// NewCollector builds the collector matching a source's engine. It returns nil
// when no audit directory is configured; the capability report states the rest.
func NewCollector(definition Definition, source connector.Scannable, events *queue.Queue, verifier collector.Verifier,
	logger *slog.Logger, observer *telemetry.Agent) *collector.Collector {
	if definition.AuditDirectory == "" {
		return nil
	}
	options := collector.Options{
		SourceKey: definition.Name, SourceID: definition.ID, Catalog: source, Queue: events,
		Verifier: verifier, Logger: logger, Metrics: observer,
	}
	switch definition.Engine {
	case EnginePostgreSQL:
		options.Reader = collector.NewPostgresReader(definition.AuditDirectory)
		options.Frontend, options.Schema = pgfrontend.Frontend{}, "public"
	case EngineMySQL:
		options.Reader = collector.NewMySQLReader(definition.AuditDirectory)
		options.Frontend, options.Schema, options.FoldCase = mysqlfrontend.Frontend{}, definition.Database, true
	case EngineMariaDB:
		options.Reader = collector.NewMariaDBReader(definition.AuditDirectory)
		options.Frontend, options.Schema, options.FoldCase = mysqlfrontend.Frontend{}, definition.Database, true
	case EngineMSSQL:
		logSource, ok := source.(connector.AuditLogSource)
		if !ok {
			return nil
		}
		options.Reader = collector.NewSQLServerReader(logSource, definition.AuditDirectory)
		options.Frontend, options.Schema, options.FoldCase = tsql.Frontend{}, "dbo", true
	default:
		return nil
	}
	return collector.New(options)
}
