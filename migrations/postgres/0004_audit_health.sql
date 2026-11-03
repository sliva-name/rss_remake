-- +goose Up
CREATE TABLE source_audit_health (
    tenant_id         uuid NOT NULL REFERENCES tenants (id),
    source_id         uuid NOT NULL,
    state             text NOT NULL,
    reason_code       text NOT NULL DEFAULT '',
    position_read_at  timestamptz,
    lost_events_total bigint NOT NULL DEFAULT 0,
    reported_at       timestamptz NOT NULL,
    PRIMARY KEY (source_id),
    FOREIGN KEY (tenant_id, source_id) REFERENCES sources (tenant_id, id)
);
ALTER TABLE source_audit_health ENABLE ROW LEVEL SECURITY;
ALTER TABLE source_audit_health FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON source_audit_health
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- +goose Down
DROP TABLE source_audit_health;
