-- +goose NO TRANSACTION
-- +goose Up
-- One row per event. ReplacingMergeTree folds rows with the same key, so a replay
-- after a crash converges to one row; queries read with FINAL to see that at once.
CREATE TABLE audit_events
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
    ingested_at           DateTime64(3, 'UTC') DEFAULT now64(3)
)
ENGINE = ReplacingMergeTree(ingested_at)
PARTITION BY toYYYYMM(event_time)
ORDER BY (tenant_id, toDate(event_time), event_id)
TTL toDateTime(event_time) + INTERVAL 13 MONTH;

-- The application always filters by tenant. This policy is the second lock: a
-- query that forgets the filter still sees one tenant, and without the setting it
-- fails instead of seeing all.
CREATE ROW POLICY tenant_isolation ON audit_events
    USING tenant_id = toUUID(getSetting('SQL_tenant_id')) TO dg_ch_app;
