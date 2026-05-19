ALTER TABLE network_change_events
    ADD COLUMN reviewed   BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN notes      TEXT;

CREATE INDEX idx_change_events_reviewed ON network_change_events (network_id, reviewed);
