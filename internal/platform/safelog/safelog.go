// Package safelog builds an slog handler that only emits allowlisted
// attributes. Blocking by default keeps a careless logger call from writing a
// query, a parameter or a driver error to the agent's log.
package safelog

import (
	"errors"
	"io"
	"log/slog"

	"dataguard/internal/platform/safeerr"
)

const redacted = "[redacted]"

// allowedKeys lists attributes whose values are identifiers, counters or
// static text by construction. The "error" key is handled separately.
var allowedKeys = map[string]bool{
	"agent_id": true, "attempt": true, "backoff": true, "batch_size": true,
	"bytes": true, "capacity_bytes": true, "code": true, "component": true,
	"count": true, "duration": true, "engine": true, "event_count": true,
	"field": true, "job_id": true, "lost_events": true, "outcome": true,
	"path": true, "pending_events": true, "policy_version": true, "reason": true,
	"rpc": true, "rule": true, "source_id": true, "source_key": true, "sources_open": true,
	"sources_refused": true, "sources_version": true,
	"state": true, "status": true, "tables": true, "tenant_id": true, "version": true,
}

const errorKey = "error"

// New returns a JSON logger writing to w.
func New(w io.Writer, level slog.Level) *slog.Logger {
	inner := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level, ReplaceAttr: filterAttr})
	return slog.New(inner)
}

func filterAttr(groups []string, attr slog.Attr) slog.Attr {
	if len(groups) == 0 && isBuiltin(attr.Key) {
		return attr
	}
	if attr.Key == errorKey {
		return slog.String(errorKey, errorText(attr.Value))
	}
	if allowedKeys[attr.Key] {
		return attr
	}
	return slog.String(attr.Key, redacted)
}

func isBuiltin(key string) bool {
	return key == slog.TimeKey || key == slog.LevelKey || key == slog.MessageKey || key == slog.SourceKey
}

// errorText prints only safe errors, because a plain error may wrap driver text.
func errorText(value slog.Value) string {
	err, ok := value.Any().(error)
	if !ok {
		return redacted
	}
	if safe, ok := errors.AsType[*safeerr.Error](err); ok {
		return safe.Error()
	}
	return redacted
}

// Discard returns a logger for tests that do not assert on output.
func Discard() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}
