// Package mssql adapts Microsoft SQL Server.
package mssql

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	_ "github.com/microsoft/go-mssqldb" // registers the sqlserver driver

	"dataguard/internal/connector"
	"dataguard/internal/connector/sqlsource"
	agentv1 "dataguard/internal/gen/dataguard/agent/v1"
	"dataguard/internal/platform/safeerr"
)

// Source is a SQL Server connection.
type Source struct {
	db       *sql.DB
	database string
	// auditPattern locates audit files on the server; empty when audit is not
	// configured for this source.
	auditPattern string
}

// Open connects without running a query.
func Open(credentials connector.Credentials, auditDirectory string, maxConnections int) (*Source, error) {
	query := url.Values{"database": {credentials.Database}, "app name": {"dataguard-scanner"}}
	switch credentials.TLS {
	case connector.TLSDisable:
		query.Set("encrypt", "disable")
	case connector.TLSRequire:
		query.Set("encrypt", "true")
		query.Set("TrustServerCertificate", "true")
	default:
		query.Set("encrypt", "true")
	}
	dsn := url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(credentials.Username, credentials.Password),
		Host:     credentials.Host + ":" + strconv.Itoa(credentials.Port),
		RawQuery: query.Encode(),
	}
	db, err := sql.Open("sqlserver", dsn.String())
	if err != nil {
		return nil, safeerr.New("open mssql source", safeerr.CodeInvalid, err)
	}
	sqlsource.Configure(db, maxConnections)
	source := &Source{db: db, database: credentials.Database}
	if auditDirectory != "" {
		source.auditPattern = strings.TrimSuffix(auditDirectory, "/") + "/*.sqlaudit"
	}
	return source, nil
}

// Close releases the pool.
func (s *Source) Close() error { return s.db.Close() }

// Probe reports discovery capabilities and the server version.
func (s *Source) Probe(ctx context.Context) (string, []*agentv1.CapabilityStatus) {
	var version string
	if err := s.db.QueryRowContext(ctx, `SELECT CAST(SERVERPROPERTY('ProductVersion') AS nvarchar(32))`).Scan(&version); err != nil {
		return "", []*agentv1.CapabilityStatus{
			connector.Status(agentv1.Capability_CAPABILITY_SCHEMA_DISCOVERY, agentv1.Support_SUPPORT_UNKNOWN, "PROBE_FAILED"),
			connector.Status(agentv1.Capability_CAPABILITY_COLUMN_PROFILING, agentv1.Support_SUPPORT_UNKNOWN, "PROBE_FAILED"),
		}
	}
	return version, append([]*agentv1.CapabilityStatus{
		connector.Status(agentv1.Capability_CAPABILITY_SCHEMA_DISCOVERY, agentv1.Support_SUPPORT_AVAILABLE, ""),
		connector.Status(agentv1.Capability_CAPABILITY_COLUMN_PROFILING, agentv1.Support_SUPPORT_AVAILABLE, ""),
	}, s.auditCapabilities(ctx)...)
}

// auditCapabilities checks what the agent can actually read. The catalog views of
// server audits are hidden from a login with only VIEW SERVER SECURITY AUDIT, so
// reading the files is the only honest probe: an empty catalog would look like
// "not configured" while events flow.
func (s *Source) auditCapabilities(ctx context.Context) []*agentv1.CapabilityStatus {
	const reason = "SERVER_AUDIT_REQUIRED"
	if s.auditPattern == "" {
		return []*agentv1.CapabilityStatus{
			connector.Status(agentv1.Capability_CAPABILITY_NATIVE_AUDIT, agentv1.Support_SUPPORT_NOT_CONFIGURED, "AUDIT_DIRECTORY_NOT_SET"),
		}
	}
	const probe = `SELECT COUNT(*), COUNT(CASE WHEN action_id = 'SL' THEN 1 END)
		FROM (SELECT TOP (1000) action_id FROM sys.fn_get_audit_file(@pattern, default, default)) recent`
	var records, reads int
	if err := s.db.QueryRowContext(ctx, probe, sql.Named("pattern", s.auditPattern)).Scan(&records, &reads); err != nil {
		return []*agentv1.CapabilityStatus{connector.Status(agentv1.Capability_CAPABILITY_NATIVE_AUDIT, agentv1.Support_SUPPORT_NOT_CONFIGURED, reason)}
	}
	readAudit := connector.Status(agentv1.Capability_CAPABILITY_READ_AUDIT, agentv1.Support_SUPPORT_AVAILABLE, "")
	if reads == 0 {
		// The file is readable but holds no SELECT yet: that may be a quiet database
		// or a specification without SELECT. The probe cannot tell which.
		readAudit = connector.Status(agentv1.Capability_CAPABILITY_READ_AUDIT, agentv1.Support_SUPPORT_UNKNOWN, "NO_READ_RECORDS_SEEN")
	}
	return []*agentv1.CapabilityStatus{
		connector.Status(agentv1.Capability_CAPABILITY_NATIVE_AUDIT, agentv1.Support_SUPPORT_AVAILABLE, ""),
		readAudit,
		connector.Status(agentv1.Capability_CAPABILITY_TABLE_LEVEL_AUDIT, agentv1.Support_SUPPORT_AVAILABLE, ""),
		connector.Status(agentv1.Capability_CAPABILITY_COLUMN_LEVEL_AUDIT, agentv1.Support_SUPPORT_AVAILABLE, "DERIVED_FROM_QUERY_TEXT"),
		connector.Status(agentv1.Capability_CAPABILITY_QUERY_TEXT, agentv1.Support_SUPPORT_AVAILABLE, ""),
		connector.Status(agentv1.Capability_CAPABILITY_EXECUTION_STATUS, agentv1.Support_SUPPORT_AVAILABLE, ""),
		connector.Status(agentv1.Capability_CAPABILITY_RETURNED_ROWS, agentv1.Support_SUPPORT_UNAVAILABLE, "NOT_IN_NATIVE_AUDIT"),
		connector.Status(agentv1.Capability_CAPABILITY_APPLICATION_CONTEXT, agentv1.Support_SUPPORT_UNAVAILABLE, "NOT_IMPLEMENTED_FOR_ENGINE"),
	}
}

const catalogQuery = `
SELECT s.name, o.name, RTRIM(o.type),
       COALESCE((SELECT SUM(p.rows) FROM sys.partitions p WHERE p.object_id = o.object_id AND p.index_id IN (0, 1)), -1),
       COALESCE(OBJECT_DEFINITION(o.object_id), ''),
       c.name, TYPE_NAME(c.user_type_id), c.column_id, c.is_nullable,
       COALESCE(CAST(ep.value AS nvarchar(4000)), '')
FROM sys.objects o
JOIN sys.schemas s ON s.schema_id = o.schema_id
JOIN sys.columns c ON c.object_id = o.object_id
LEFT JOIN sys.extended_properties ep
  ON ep.major_id = c.object_id AND ep.minor_id = c.column_id AND ep.class = 1 AND ep.name = 'MS_Description'
WHERE o.type IN ('U', 'V') AND o.is_ms_shipped = 0
ORDER BY s.name, o.name, c.column_id`

// Tables lists user tables and views of the connected database.
func (s *Source) Tables(ctx context.Context) ([]connector.Table, error) {
	rows, err := s.db.QueryContext(ctx, catalogQuery)
	if err != nil {
		return nil, safeerr.New("read catalog", safeerr.CodeQuery, err)
	}
	defer func() { _ = rows.Close() }()

	var tables []connector.Table
	for rows.Next() {
		var schema, name, kind, definition string
		var estimate int64
		var ordinal int32
		var column connector.Column
		if err := rows.Scan(&schema, &name, &kind, &estimate, &definition, &column.Name, &column.NativeType,
			&ordinal, &column.Nullable, &column.Comment); err != nil {
			return nil, safeerr.New("decode catalog row", safeerr.CodeQuery, err)
		}
		column.Ordinal = uint32(ordinal)
		last := len(tables) - 1
		if last < 0 || tables[last].Schema != schema || tables[last].Name != name {
			tables = append(tables, connector.Table{
				Database: s.database, Schema: schema, Name: name, Kind: tableKind(kind),
				EstimatedRows: estimate, Definition: definition,
			})
			last++
		}
		tables[last].Columns = append(tables[last].Columns, column)
	}
	if err := rows.Err(); err != nil {
		return nil, safeerr.New("read catalog", safeerr.CodeQuery, err)
	}
	return tables, nil
}

func tableKind(kind string) agentv1.TableKind {
	if kind == "V" {
		return agentv1.TableKind_TABLE_KIND_VIEW
	}
	return agentv1.TableKind_TABLE_KIND_TABLE
}

// Sample reads a bounded sample.
func (s *Source) Sample(ctx context.Context, table connector.Table, columns []connector.Column, limits connector.Limits, visit connector.Visitor) (connector.SampleStats, error) {
	return sqlsource.Sample(ctx, s.db, dialect{}, table, columns, limits, visit)
}

// maxAuditRows bounds one read of the audit log.
const maxAuditRows = 5000

// AuditRows reads audit records. fn_get_audit_file takes the start position as a
// pair, so a fresh read passes neither.
func (s *Source) AuditRows(ctx context.Context, pattern, file string, offset int64) ([]connector.AuditRow, error) {
	const columns = `SELECT TOP (@limit) file_name, audit_file_offset, event_time, sequence_number, succeeded,
		session_id, transaction_id, server_principal_name, COALESCE(client_ip, ''), COALESCE(schema_name, ''), statement `
	// TOP needs an order to page by: the cursor assumes file and offset order.
	const order = ` ORDER BY file_name, audit_file_offset, event_time, sequence_number`
	query := columns + `FROM sys.fn_get_audit_file(@pattern, default, default)` + order
	arguments := []any{sql.Named("limit", maxAuditRows), sql.Named("pattern", pattern)}
	if file != "" {
		query = columns + `FROM sys.fn_get_audit_file(@pattern, @file, @offset)` + order
		arguments = append(arguments, sql.Named("file", file), sql.Named("offset", offset))
	}
	rows, err := s.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, safeerr.New("read audit log", safeerr.CodeQuery, err)
	}
	defer func() { _ = rows.Close() }()

	var result []connector.AuditRow
	for rows.Next() {
		var row connector.AuditRow
		var session int16
		var schema string
		if err := rows.Scan(&row.File, &row.Offset, &row.Time, &row.Sequence, &row.Succeeded, &session,
			&row.Transaction, &row.Principal, &row.ClientAddress, &schema, &row.Statement); err != nil {
			return nil, safeerr.New("decode audit row", safeerr.CodeQuery, err)
		}
		row.Session = int(session)
		row.UserObject = schema != "sys" && schema != "INFORMATION_SCHEMA" && row.Statement != ""
		result = append(result, row)
	}
	if err := rows.Err(); err != nil {
		return nil, safeerr.New("read audit log", safeerr.CodeQuery, err)
	}
	return result, nil
}

type dialect struct{}

func (dialect) Quote(identifier string) string {
	return sqlsource.QuoteWith(identifier, "[", "]")
}

// SampleQuery samples pages when the table outgrows the limit. Unread rows are
// the reason TOP alone would bias towards the clustered index order.
func (d dialect) SampleQuery(table connector.Table, quotedColumns []string, maxRows uint64) (string, agentv1.SamplingMethod) {
	const samplePadding = 3.0
	list := strings.Join(quotedColumns, ", ")
	target := d.Quote(table.Schema) + "." + d.Quote(table.Name)
	if table.EstimatedRows <= int64(maxRows) {
		return fmt.Sprintf(`SELECT TOP (%d) %s FROM %s`, maxRows, list, target), agentv1.SamplingMethod_SAMPLING_METHOD_BOUNDED_PREFIX
	}
	percent := min(100, samplePadding*100*float64(maxRows)/float64(table.EstimatedRows))
	return fmt.Sprintf(`SELECT TOP (%d) %s FROM %s TABLESAMPLE (%.6f PERCENT)`, maxRows, list, target, percent),
		agentv1.SamplingMethod_SAMPLING_METHOD_ENGINE_SAMPLE
}

// TxOptions relies on grants for read-only access, because the driver has no
// read-only transactions. READ UNCOMMITTED keeps the scan from taking shared
// locks that would block writers; a dirty value is harmless to classification.
func (dialect) TxOptions() *sql.TxOptions {
	return &sql.TxOptions{Isolation: sql.LevelReadUncommitted}
}

func (dialect) Prepare(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, fmt.Sprintf(`SET LOCK_TIMEOUT %d`, sqlsource.LockTimeout.Milliseconds()))
	return err
}
