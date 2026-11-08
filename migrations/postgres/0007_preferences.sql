-- +goose Up
-- Personal settings of one account in one organization: saved views,
-- favourites, recently opened objects, overview layout (ADR-0010). They hold
-- references and filters, never data values.
CREATE TABLE user_preferences (
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    subject    text NOT NULL,
    key        text NOT NULL CHECK (key IN ('views', 'favorites', 'recent', 'overview')),
    value      jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, subject, key)
);

-- Two locks: the organization, like every tenant table, and the account. A
-- query that forgets to set the account sees nothing rather than everyone's.
ALTER TABLE user_preferences ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_preferences FORCE ROW LEVEL SECURITY;
CREATE POLICY owner_only ON user_preferences
    USING (tenant_id = current_tenant_id() AND subject = current_setting('app.subject', true))
    WITH CHECK (tenant_id = current_tenant_id() AND subject = current_setting('app.subject', true));

GRANT DELETE ON user_preferences TO dg_runtime;

-- +goose Down
DROP TABLE user_preferences;
