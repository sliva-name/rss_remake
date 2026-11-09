-- +goose Up
-- The journal of operator actions (internal/core/oplog). Each entry is written
-- in the transaction of the change it describes. Details hold field names and
-- versions, never data values or passwords.
CREATE TABLE operator_actions (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    at            timestamptz NOT NULL DEFAULT now(),
    actor_subject text NOT NULL,
    actor_name    text NOT NULL,
    action        text NOT NULL,
    object_id     uuid NOT NULL,
    object_label  text NOT NULL,
    details       jsonb NOT NULL DEFAULT '{}'
);

-- Ids are UUIDv7, so their order is the order of the actions.
CREATE INDEX operator_actions_recent ON operator_actions (tenant_id, id DESC);
CREATE INDEX operator_actions_of_object ON operator_actions (tenant_id, object_id, id DESC);

ALTER TABLE operator_actions ENABLE ROW LEVEL SECURITY;
ALTER TABLE operator_actions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON operator_actions
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- The journal only grows: even a compromised server cannot rewrite who did what.
REVOKE UPDATE, DELETE, TRUNCATE ON operator_actions FROM dg_runtime;

-- Who issued a token, so the agent enrolled with it is attributed to them.
ALTER TABLE enrollment_tokens
    ADD COLUMN created_by_subject text NOT NULL DEFAULT '',
    ADD COLUMN created_by_name text NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE enrollment_tokens DROP COLUMN created_by_subject, DROP COLUMN created_by_name;
DROP TABLE operator_actions;
