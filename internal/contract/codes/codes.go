// Package codes lists every machine-readable code that reaches an operator in
// the dashboard. Each one names what happened and needs an explanation with a
// way out; web/dashboard/src/failures.json holds them, and a test keeps the two
// in step, so a new code cannot reach the interface unexplained. A code meant for
// the dashboard is declared here, not as a literal at the place it is produced.
package codes

import "dataguard/internal/platform/safeerr"

// Why the agent did not open a source from the center's list.
const (
	TargetNotAllowed         = "TARGET_NOT_ALLOWED"
	AuditDirectoryNotAllowed = "AUDIT_DIRECTORY_NOT_ALLOWED"
	CredentialUnreadable     = "CREDENTIAL_UNREADABLE" //nolint:gosec // A status code, not a credential.
	InvalidDefinition        = "INVALID_DEFINITION"
	OpenFailed               = "OPEN_FAILED"
	ConnectionFailed         = "CONNECTION_FAILED"
)

// Why audit collection of a source is not observing.
const (
	AgentSilent          = "AGENT_SILENT"
	NoHealthReports      = "NO_HEALTH_REPORTS"
	AuditDirectoryNotSet = "AUDIT_DIRECTORY_NOT_SET"
	NotStarted           = "NOT_STARTED"
	QueueFull            = "QUEUE_FULL"
	LogUnreadable        = "LOG_UNREADABLE"
	CatalogUnavailable   = "CATALOG_UNAVAILABLE"
	LogTimeZoneUnknown   = "LOG_TIME_ZONE_UNKNOWN"
	StoreFailed          = "STORE_FAILED"
)

// Why a source lacks a capability, or how the capability is limited.
const (
	ProbeFailed                 = "PROBE_FAILED"
	PgauditWithJSONLogRequired  = "PGAUDIT_WITH_JSONLOG_REQUIRED"
	PgauditReadClassRequired    = "PGAUDIT_READ_CLASS_REQUIRED"
	PgauditMiscSetClassRequired = "PGAUDIT_MISC_SET_CLASS_REQUIRED"
	LogDisconnectionsRequired   = "LOG_DISCONNECTIONS_REQUIRED"
	GeneralLogRequired          = "GENERAL_LOG_REQUIRED"
	GeneralLogHasNoOutcome      = "GENERAL_LOG_HAS_NO_OUTCOME"
	ServerAuditRequired         = "SERVER_AUDIT_REQUIRED"
	SQLServerAuditRequired      = "SQL_SERVER_AUDIT_REQUIRED"
	NoReadRecordsSeen           = "NO_READ_RECORDS_SEEN"
	DerivedFromQueryText        = "DERIVED_FROM_QUERY_TEXT"
	NotInNativeAudit            = "NOT_IN_NATIVE_AUDIT"
	NotImplementedForEngine     = "NOT_IMPLEMENTED_FOR_ENGINE"
)

// Why a scan job failed or was cancelled, besides the safeerr codes the agent
// reports for a failed read.
const (
	UnknownSource = "UNKNOWN_SOURCE"
	LeaseExpired  = "LEASE_EXPIRED"
	SourceDeleted = "SOURCE_DELETED"
)

// All returns every code the dashboard may show. Gap reasons are not here: they
// are a protobuf enum, and the test takes them from the contract.
func All() []string {
	all := []string{
		TargetNotAllowed, AuditDirectoryNotAllowed, CredentialUnreadable, InvalidDefinition, OpenFailed, ConnectionFailed,
		AgentSilent, NoHealthReports, AuditDirectoryNotSet, NotStarted, QueueFull, LogUnreadable, CatalogUnavailable,
		LogTimeZoneUnknown, StoreFailed,
		ProbeFailed, PgauditWithJSONLogRequired, PgauditReadClassRequired, PgauditMiscSetClassRequired,
		LogDisconnectionsRequired, GeneralLogRequired, GeneralLogHasNoOutcome, ServerAuditRequired,
		SQLServerAuditRequired, NoReadRecordsSeen, DerivedFromQueryText, NotInNativeAudit, NotImplementedForEngine,
		UnknownSource, LeaseExpired, SourceDeleted,
	}
	for _, code := range safeerr.Codes() {
		all = append(all, string(code))
	}
	return all
}
