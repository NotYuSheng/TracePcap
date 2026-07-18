-- ── Carry-forward + staleness for human adjudication overrides (#499 monitor mode) ──
-- Human overrides on the adjudication layer (host-identity, host-hardware, host-service,
-- host-behaviour) used to be strictly per-file. In monitor mode a human's correction should behave
-- like a confirmed node-role label: carry forward to the next snapshot and go STALE when the
-- evidence that would re-classify the node drifts (MAC / new protocols / new external orgs).
--
-- These columns mirror the node_roles staleness model (V37/#369):
--   origin               MANUAL (set directly on this file) | CARRIED_FORWARD (copied from prev snapshot)
--   observed_properties  JSON baseline snapshotted when carried, diffed against the new pcap
--   stale_since          when the carried override first drifted (sticky until re-affirmed/cleared)
--   stale_fields         JSON array of the human-readable changes that made it stale
ALTER TABLE human_overrides
    ADD COLUMN origin              VARCHAR(20) NOT NULL DEFAULT 'MANUAL',
    ADD COLUMN observed_properties JSONB,
    ADD COLUMN stale_since         TIMESTAMP,
    ADD COLUMN stale_fields        JSONB;

-- Carried rows are regenerated per snapshot; index the path that finds them for a file.
CREATE INDEX idx_human_override_origin ON human_overrides (file_id, origin);
