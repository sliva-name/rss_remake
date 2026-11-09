-- +goose Up
-- Epochs of the policy signing key (ADR-0014). Everything before rotation was
-- signed by the first key, epoch 1.
ALTER TABLE policies ADD COLUMN key_epoch integer NOT NULL DEFAULT 1;
-- The epoch the agent trusts, from its heartbeat.
ALTER TABLE agents ADD COLUMN policy_key_epoch integer NOT NULL DEFAULT 1;

-- +goose Down
ALTER TABLE agents DROP COLUMN policy_key_epoch;
ALTER TABLE policies DROP COLUMN key_epoch;
