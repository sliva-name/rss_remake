-- +goose Up
-- The scan schedule of a source (ADR-0016): the center queues a scan of it every
-- scan_every_hours, next at next_scan_at. Both are empty while scans start only
-- by hand.
ALTER TABLE sources
    ADD COLUMN scan_every_hours integer CHECK (scan_every_hours BETWEEN 1 AND 720),
    ADD COLUMN next_scan_at timestamptz,
    ADD CONSTRAINT sources_scan_schedule CHECK ((scan_every_hours IS NULL) = (next_scan_at IS NULL));

-- The scheduler reads only the sources whose time may have come.
CREATE INDEX sources_scan_due ON sources (next_scan_at) WHERE next_scan_at IS NOT NULL AND deleted_at IS NULL;

-- A scan the center queued by schedule rather than at someone's request.
ALTER TABLE scan_jobs ADD COLUMN scheduled boolean NOT NULL DEFAULT false;

-- +goose Down
ALTER TABLE scan_jobs DROP COLUMN scheduled;
DROP INDEX sources_scan_due;
ALTER TABLE sources DROP CONSTRAINT sources_scan_schedule, DROP COLUMN next_scan_at, DROP COLUMN scan_every_hours;
