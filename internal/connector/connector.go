// Package connector defines what the platform can ask of a database. A source
// implements only the small interfaces it can honor, so missing functionality
// is visible as a missing capability rather than hidden behind a stub.
package connector

import (
	"context"

	"golang.org/x/time/rate"

	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
)

// Column describes a column. Comment stays on the agent.
type Column struct {
	Name       string
	NativeType string
	Comment    string
	Ordinal    uint32
	Nullable   bool
}

// Table describes a table or view. Definition holds a view's source text, which
// is needed to resolve queries but can embed literals, so it never leaves the
// agent. EstimatedRows is negative when the engine has no statistics.
type Table struct {
	Database      string
	Schema        string
	Name          string
	Kind          agentv1.TableKind
	Columns       []Column
	EstimatedRows int64
	Definition    string
}

// Limits bound a single table read.
type Limits struct {
	MaxRows  uint64
	MaxBytes uint64
	// Limiter throttles rows per second across all concurrent reads of a job.
	Limiter *rate.Limiter
}

// SampleStats summarizes a read.
type SampleStats struct {
	Rows   uint64
	Method agentv1.SamplingMethod
	// Truncated means MaxBytes stopped the read before the sample was complete.
	Truncated bool
}

// Visitor receives one non-null value. The slice is valid only during the call
// and is wiped afterwards, so a visitor must not retain it.
type Visitor func(columnIndex int, value []byte)

// Source is an open connection to a database.
type Source interface {
	Close() error
}

// Prober reports the engine version and what this instance can do.
type Prober interface {
	Probe(ctx context.Context) (version string, capabilities []*agentv1.CapabilityStatus)
}

// Catalog lists tables and columns.
type Catalog interface {
	Tables(ctx context.Context) ([]Table, error)
}

// Sampler reads a bounded sample of values.
type Sampler interface {
	Sample(ctx context.Context, table Table, columns []Column, limits Limits, visit Visitor) (SampleStats, error)
}

// Scannable is what the discovery scanner needs.
type Scannable interface {
	Source
	Prober
	Catalog
	Sampler
}

// TLSMode says how to protect the connection to the database.
type TLSMode string

const (
	// TLSVerifyFull is the default: encrypted and the server identity is checked.
	TLSVerifyFull TLSMode = "verify-full"
	// TLSRequire encrypts without checking identity.
	TLSRequire TLSMode = "require"
	// TLSDisable sends credentials in clear text and suits only a local network.
	TLSDisable TLSMode = "disable"
)

// Credentials are the parameters of a connection.
type Credentials struct {
	Host     string
	Port     int
	Database string
	Username string
	Password string
	TLS      TLSMode
}

// Status is shorthand for building a capability entry.
func Status(capability agentv1.Capability, support agentv1.Support, reason string) *agentv1.CapabilityStatus {
	return &agentv1.CapabilityStatus{Capability: capability, Support: support, ReasonCode: reason}
}
