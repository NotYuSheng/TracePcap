-- ── node_roles staleness baseline (#369) ──────────────────────────────────────
-- When a human confirms a role label we snapshot the node's key properties at that
-- moment (the baseline). On each new snapshot analysis the current properties are
-- compared against this baseline; if MAC, dominant protocols or external orgs drift,
-- the label is flagged stale so the analyst can re-confirm or update it.

ALTER TABLE node_roles
    ADD COLUMN labeled_at          TIMESTAMP,           -- when the human confirmed the label
    ADD COLUMN baseline_file_id    UUID,                -- file the baseline properties were computed from
    ADD COLUMN baseline_properties JSONB,               -- { mac, deviceType, protocols:[], orgs:[] } at label time
    ADD COLUMN stale_since         TIMESTAMP,           -- first time drift was detected (null = not stale)
    ADD COLUMN stale_fields        JSONB;               -- human-readable list of what changed since the baseline
