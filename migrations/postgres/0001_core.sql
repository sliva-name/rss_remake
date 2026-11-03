-- +goose Up
CREATE FUNCTION current_tenant_id() RETURNS uuid
    LANGUAGE sql STABLE
    AS $$ SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid $$;

CREATE TABLE tenants (
    id         uuid PRIMARY KEY,
    name       text NOT NULL UNIQUE CHECK (length(name) BETWEEN 1 AND 200),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE environments (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 100),
    kind       text NOT NULL CHECK (kind IN ('development', 'testing', 'production')),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name),
    UNIQUE (tenant_id, id)
);

CREATE TABLE enrollment_tokens (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    environment_id uuid NOT NULL,
    -- SHA-256 is enough here: the token is 256 random bits, not a password.
    token_hash     bytea NOT NULL UNIQUE,
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,
    created_at     timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id)
);

CREATE TABLE agents (
    id                  uuid PRIMARY KEY,
    tenant_id           uuid NOT NULL REFERENCES tenants (id),
    environment_id      uuid NOT NULL,
    status              text NOT NULL CHECK (status IN ('active', 'revoked')),
    version             text NOT NULL DEFAULT '',
    certificate_expires timestamptz NOT NULL,
    last_seen_at        timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    revoked_at          timestamptz,
    FOREIGN KEY (tenant_id, environment_id) REFERENCES environments (tenant_id, id),
    UNIQUE (tenant_id, id)
);

CREATE TABLE sources (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL REFERENCES tenants (id),
    agent_id       uuid NOT NULL,
    source_key     text NOT NULL,
    engine         text NOT NULL,
    engine_version text NOT NULL DEFAULT '',
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, agent_id) REFERENCES agents (tenant_id, id),
    UNIQUE (agent_id, source_key),
    UNIQUE (tenant_id, id)
);

CREATE TABLE source_capabilities (
    tenant_id   uuid NOT NULL REFERENCES tenants (id),
    source_id   uuid NOT NULL,
    capability  text NOT NULL,
    support     text NOT NULL,
    reason_code text NOT NULL DEFAULT '',
    observed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source_id, capability),
    FOREIGN KEY (tenant_id, source_id) REFERENCES sources (tenant_id, id)
);

CREATE TABLE policies (
    tenant_id  uuid NOT NULL REFERENCES tenants (id),
    version    bigint NOT NULL CHECK (version > 0),
    payload    bytea NOT NULL,
    signature  bytea NOT NULL,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, version)
);

-- Listing all organizations is the one read that must cross tenants, so it is
-- a narrow definer function instead of a hole in the row policy.
-- +goose StatementBegin
CREATE FUNCTION platform_list_tenants()
    RETURNS TABLE (id uuid, name text, created_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
    AS $$ SELECT id, name, created_at FROM tenants ORDER BY name $$;
-- +goose StatementEnd
REVOKE ALL ON FUNCTION platform_list_tenants() FROM PUBLIC;

-- +goose StatementBegin
DO $$
DECLARE
    tenant_table text;
BEGIN
    FOREACH tenant_table IN ARRAY ARRAY[
        'environments', 'enrollment_tokens', 'agents', 'sources',
        'source_capabilities', 'policies'
    ] LOOP
        EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', tenant_table);
        EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', tenant_table);
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_tenant_id()) '
            'WITH CHECK (tenant_id = current_tenant_id())', tenant_table);
    END LOOP;
END $$;
-- +goose StatementEnd

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenants
    USING (id = current_tenant_id())
    WITH CHECK (id = current_tenant_id());

-- +goose Down
DROP TABLE policies, source_capabilities, sources, agents, enrollment_tokens, environments, tenants;
DROP FUNCTION platform_list_tenants();
DROP FUNCTION current_tenant_id();
