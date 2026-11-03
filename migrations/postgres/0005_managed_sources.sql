-- +goose Up
-- Sources are defined in the center (ADR-0006). The password is sealed to the
-- serving agent's key, so the center stores only ciphertext.
ALTER TABLE agents
    ADD COLUMN sealing_public_key bytea,
    ADD COLUMN sources_version bigint NOT NULL DEFAULT 0;

ALTER TABLE sources
    ADD COLUMN host text NOT NULL DEFAULT '',
    ADD COLUMN port integer NOT NULL DEFAULT 0,
    ADD COLUMN database_name text NOT NULL DEFAULT '',
    ADD COLUMN username text NOT NULL DEFAULT '',
    ADD COLUMN tls_mode text NOT NULL DEFAULT 'verify-full'
        CHECK (tls_mode IN ('verify-full', 'require', 'disable')),
    ADD COLUMN audit_directory text NOT NULL DEFAULT '',
    ADD COLUMN max_connections integer NOT NULL DEFAULT 2 CHECK (max_connections BETWEEN 1 AND 8),
    ADD COLUMN sealed_password bytea,
    ADD COLUMN status_code text NOT NULL DEFAULT '',
    ADD COLUMN probed_at timestamptz,
    ADD COLUMN deleted_at timestamptz;

-- Sources reported from agent files before ADR-0006 have no definition. Their
-- history stays, but no agent serves them any more.
UPDATE sources SET deleted_at = now() WHERE sealed_password IS NULL;

ALTER TABLE sources DROP CONSTRAINT sources_agent_id_source_key_key;
CREATE UNIQUE INDEX sources_live_name ON sources (tenant_id, source_key) WHERE deleted_at IS NULL;

-- +goose Down
DROP INDEX sources_live_name;
ALTER TABLE sources ADD CONSTRAINT sources_agent_id_source_key_key UNIQUE (agent_id, source_key);
ALTER TABLE sources
    DROP COLUMN host, DROP COLUMN port, DROP COLUMN database_name, DROP COLUMN username,
    DROP COLUMN tls_mode, DROP COLUMN audit_directory, DROP COLUMN max_connections,
    DROP COLUMN sealed_password, DROP COLUMN status_code, DROP COLUMN probed_at, DROP COLUMN deleted_at;
ALTER TABLE agents DROP COLUMN sealing_public_key, DROP COLUMN sources_version;
