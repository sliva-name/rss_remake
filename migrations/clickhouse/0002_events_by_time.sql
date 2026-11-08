-- +goose NO TRANSACTION
-- +goose Up
-- ADR-0007. Duplicates are refused at ingest, so the table no longer folds them
-- and nothing reads it with FINAL. The key follows time, so a search stops at the
-- first page; the projection answers reports for whole hours.
DROP TABLE IF EXISTS audit_events_next;

CREATE TABLE audit_events_next
(
    tenant_id             UUID,
    event_id              UUID,
    event_time            DateTime64(6, 'UTC'),
    event_type            LowCardinality(String),
    agent_id              UUID,
    source_id             UUID,
    database_principal    String,
    application_principal String,
    application_id        LowCardinality(String),
    identity_confidence   LowCardinality(String),
    client_address        String,
    operation             LowCardinality(String),
    tables                Array(String),
    columns               Array(String),
    column_ids            Array(UUID),
    categories            Array(LowCardinality(String)),
    query_fingerprint     String,
    execution_status      LowCardinality(String),
    error_code            LowCardinality(String),
    evidence_level        LowCardinality(String),
    object_resolution     LowCardinality(String),
    session_id            String,
    transaction_id        String,
    trace_id              String,
    gap_reason            LowCardinality(String),
    gap_lost_events       Nullable(UInt64),
    ingested_at           DateTime64(3, 'UTC') DEFAULT now64(3),
    PROJECTION hourly
    (
        SELECT tenant_id, toStartOfHour(event_time), source_id, database_principal, application_principal,
               identity_confidence, event_type, execution_status, object_resolution, categories,
               count(), max(event_time)
        GROUP BY tenant_id, toStartOfHour(event_time), source_id, database_principal, application_principal,
               identity_confidence, event_type, execution_status, object_resolution, categories
    )
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, event_time, event_id)
TTL toDateTime(event_time) + INTERVAL 13 MONTH;

INSERT INTO audit_events_next SELECT * FROM audit_events FINAL;

-- The row policy is bound to the name, so it keeps guarding the new table.
EXCHANGE TABLES audit_events AND audit_events_next;

DROP TABLE audit_events_next;
