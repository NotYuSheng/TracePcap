-- The per-range label was a free-text memo that nothing consumed; drop it.
ALTER TABLE custom_private_ranges
    DROP COLUMN label;
