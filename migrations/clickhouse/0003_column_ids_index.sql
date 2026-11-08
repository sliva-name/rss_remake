-- +goose NO TRANSACTION
-- +goose Up
-- Object pages filter events by a column or a table. Without an index such a
-- filter reads every row of the window; the bloom filter lets ClickHouse skip
-- the parts that cannot hold the column. About 2 % of the table's size.
ALTER TABLE audit_events ADD INDEX IF NOT EXISTS column_ids_bloom column_ids TYPE bloom_filter(0.01) GRANULARITY 4;

-- Parts written before the index get it in the background.
ALTER TABLE audit_events MATERIALIZE INDEX column_ids_bloom;
