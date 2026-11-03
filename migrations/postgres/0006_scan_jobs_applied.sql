-- +goose Up
-- Ingest reads the latest applied scan of a source for every batch of events to
-- know whether its cached catalog is still current.
CREATE INDEX scan_jobs_applied ON scan_jobs (source_id, finished_at DESC) WHERE status IN ('completed', 'partial');

-- +goose Down
DROP INDEX scan_jobs_applied;
