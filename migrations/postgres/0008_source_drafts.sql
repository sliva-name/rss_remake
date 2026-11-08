-- +goose Up
-- A draft is a source being checked before it is saved. Its agent opens and
-- probes it but neither scans it nor reads its audit log, and it stays out of
-- lists and reports until it is activated.
ALTER TABLE sources ADD COLUMN draft boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE sources DROP COLUMN draft;
