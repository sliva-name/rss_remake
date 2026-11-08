-- +goose Up
-- The contract version of the agent's last accepted heartbeat, and the version
-- the center refused since then, if any (ADR-0012). Agents enrolled before the
-- column speak version 1, the only one there was.
ALTER TABLE agents
    ADD COLUMN contract_version integer NOT NULL DEFAULT 1,
    ADD COLUMN refused_contract_version integer;

-- +goose Down
ALTER TABLE agents DROP COLUMN contract_version, DROP COLUMN refused_contract_version;
