-- +goose Up
CREATE TABLE asset_tables (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    source_id     uuid NOT NULL,
    database_name text NOT NULL,
    schema_name   text NOT NULL,
    table_name    text NOT NULL,
    kind          text NOT NULL,
    fingerprint   text NOT NULL,
    status        text NOT NULL CHECK (status IN ('active', 'removed')),
    first_seen_at timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, source_id) REFERENCES sources (tenant_id, id),
    UNIQUE (tenant_id, id)
);
-- Only live objects must be unique: a removed table may reappear under its name.
CREATE UNIQUE INDEX asset_tables_active_name ON asset_tables (source_id, database_name, schema_name, table_name)
    WHERE status = 'active';

CREATE TABLE asset_columns (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    table_id      uuid NOT NULL,
    column_name   text NOT NULL,
    native_type   text NOT NULL,
    ordinal       integer NOT NULL,
    nullable      boolean NOT NULL,
    status        text NOT NULL CHECK (status IN ('active', 'removed')),
    first_seen_at timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, table_id) REFERENCES asset_tables (tenant_id, id),
    UNIQUE (tenant_id, id)
);
CREATE UNIQUE INDEX asset_columns_active_name ON asset_columns (table_id, column_name) WHERE status = 'active';

CREATE TABLE asset_renames (
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    object_kind text NOT NULL CHECK (object_kind IN ('table', 'column')),
    object_id   uuid NOT NULL,
    old_name    text NOT NULL,
    new_name    text NOT NULL,
    detected_at timestamptz NOT NULL,
    -- The match is heuristic, so history records how it was made.
    detected_by text NOT NULL
);
CREATE INDEX asset_renames_object ON asset_renames (object_id);

CREATE TABLE classifications (
    tenant_id       uuid NOT NULL REFERENCES tenants (id),
    column_id       uuid NOT NULL,
    category_id     text NOT NULL,
    status          text NOT NULL CHECK (status IN ('detected', 'not_detected')),
    confidence      double precision NOT NULL,
    name_match      boolean NOT NULL,
    context_match   boolean NOT NULL,
    format_ratio    double precision NOT NULL,
    checksum_ratio  double precision,
    rows_inspected  bigint NOT NULL,
    rows_non_null   bigint NOT NULL,
    rows_matched    bigint NOT NULL,
    unique_estimate bigint NOT NULL,
    sampling_method text NOT NULL,
    first_seen_at   timestamptz NOT NULL,
    updated_at      timestamptz NOT NULL,
    PRIMARY KEY (column_id, category_id),
    FOREIGN KEY (tenant_id, column_id) REFERENCES asset_columns (tenant_id, id)
);

CREATE TABLE scan_jobs (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenants (id),
    source_id    uuid NOT NULL,
    status       text NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'partial', 'failed', 'cancelled')),
    requested_by text NOT NULL,
    attempts     integer NOT NULL DEFAULT 0,
    lease_until  timestamptz,
    failure_code text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL,
    started_at   timestamptz,
    finished_at  timestamptz,
    FOREIGN KEY (tenant_id, source_id) REFERENCES sources (tenant_id, id),
    UNIQUE (tenant_id, id)
);
CREATE INDEX scan_jobs_runnable ON scan_jobs (source_id) WHERE status IN ('pending', 'running');

CREATE TABLE scan_skipped_tables (
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    job_id        uuid NOT NULL,
    database_name text NOT NULL,
    schema_name   text NOT NULL,
    table_name    text NOT NULL,
    reason_code   text NOT NULL,
    FOREIGN KEY (tenant_id, job_id) REFERENCES scan_jobs (tenant_id, id)
);

CREATE TABLE catalog_changes (
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    occurred_at timestamptz NOT NULL,
    job_id      uuid NOT NULL,
    kind        text NOT NULL,
    table_id    uuid NOT NULL,
    column_id   uuid,
    category_id text NOT NULL DEFAULT '',
    FOREIGN KEY (tenant_id, job_id) REFERENCES scan_jobs (tenant_id, id)
);
CREATE INDEX catalog_changes_recent ON catalog_changes (tenant_id, occurred_at DESC);

-- +goose StatementBegin
DO $$
DECLARE
    tenant_table text;
BEGIN
    FOREACH tenant_table IN ARRAY ARRAY[
        'asset_tables', 'asset_columns', 'asset_renames', 'classifications',
        'scan_jobs', 'scan_skipped_tables', 'catalog_changes'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tenant_table);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tenant_table);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant_id()) '
            'WITH CHECK (tenant_id = current_tenant_id())', tenant_table);
    END LOOP;
END $$;
-- +goose StatementEnd

-- +goose Down
DROP TABLE catalog_changes, scan_skipped_tables, scan_jobs, classifications, asset_renames, asset_columns, asset_tables;
