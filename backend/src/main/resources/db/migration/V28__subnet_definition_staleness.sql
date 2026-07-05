-- ── subnet_definitions staleness baseline (#363) ─────────────────────────────
-- Mirrors the node-role staleness model (V24): when an analyst confirms a subnet's label we
-- snapshot the subnet's COMPOSITION at that moment (dominant member device types + protocols).
-- On each new snapshot the current composition is compared against this baseline; if the mix
-- drifts (new device types, protocols appearing/leaving) the label is flagged stale so the analyst
-- can re-confirm or update it. Composition drift — not membership churn — is the trigger.

ALTER TABLE subnet_definitions
    ADD COLUMN labeled_at            TIMESTAMP,   -- when the human confirmed the label
    ADD COLUMN baseline_file_id      UUID,        -- file the baseline composition was computed from
    ADD COLUMN baseline_composition  JSONB,       -- { deviceTypes:[], protocols:[], memberCount } at label time
    ADD COLUMN stale_since           TIMESTAMP,   -- first time drift was detected (null = not stale)
    ADD COLUMN stale_fields          JSONB;       -- human-readable list of what changed since the baseline
