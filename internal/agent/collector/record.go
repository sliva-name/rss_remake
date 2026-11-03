// Package collector reads native audit logs and turns them into events. Raw
// statement text exists only in memory between the reader and the analyzer.
package collector

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

// Statement is query text as read from a log. It contains literals, so every way
// of printing it is disabled; Reveal is the single, greppable exit.
type Statement struct {
	text string
}

// NewStatement wraps raw text.
func NewStatement(text string) Statement { return Statement{text: text} }

// Reveal returns the text for analysis. Nothing else may call it.
func (s Statement) Reveal() string { return s.text }

// IsEmpty reports whether there is any text.
func (s Statement) IsEmpty() bool { return s.text == "" }

const redacted = "[statement]"

// MarshalText keeps the text out of any encoder, not only fmt and slog.
func (Statement) MarshalText() ([]byte, error) { return []byte(redacted), nil }

func (Statement) String() string             { return redacted }
func (Statement) GoString() string           { return redacted }
func (Statement) LogValue() slog.Value       { return slog.StringValue(redacted) }
func (Statement) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// Kind says what a record describes.
type Kind int

const (
	KindStatement Kind = iota
	KindLogin
)

// Record is one audited action, normalized across engines.
type Record struct {
	// Position identifies the record in the source log. The event id derives from
	// it, so reading the same record twice yields the same event.
	Position      string
	Kind          Kind
	Time          time.Time
	Statement     Statement
	Principal     string
	ClientAddress string
	Session       string
	Transaction   string
	Status        agentv1.ExecutionStatus
	ErrorCode     string
	ContextToken  string
}

// Batch is what one read produced.
type Batch struct {
	Records []Record
	// Cursor is the durable position: replaying from it never skips a record.
	Cursor []byte
	// Gap is set when records were lost before this batch.
	Gap *agentv1.AuditGap
	// Unparseable counts log lines that could not be decoded.
	Unparseable uint64
}

// Reader yields audit records from one source. Implementations keep their own
// live position and treat the cursor as the point to resume after a restart.
type Reader interface {
	Read(ctx context.Context, cursor []byte) (Batch, error)
	// Rewind drops the live position. The collector calls it when a batch could not
	// be stored, so the next Read starts over from the durable cursor; otherwise
	// that batch would be skipped.
	Rewind()
}
