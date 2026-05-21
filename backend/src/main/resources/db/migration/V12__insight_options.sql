-- Add audience and focus columns to track how each insight was generated
ALTER TABLE network_insights
    ADD COLUMN IF NOT EXISTS audience VARCHAR(20),
    ADD COLUMN IF NOT EXISTS focus    VARCHAR(20);

ALTER TABLE snapshot_insights
    ADD COLUMN IF NOT EXISTS audience VARCHAR(20),
    ADD COLUMN IF NOT EXISTS focus    VARCHAR(20);
