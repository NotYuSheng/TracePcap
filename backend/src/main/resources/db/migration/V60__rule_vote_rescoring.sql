-- #925 decision (2026-11-11): Re-apply re-scores detection rules' device-type votes.
-- The classifier's vote is additive, so keeping each host's full score board (points and
-- reasons per device type) and the rule votes in it lets a rule change be re-scored exactly,
-- without the analysis-time inputs: new = board - old rule votes + current rule votes.
ALTER TABLE host_classifications
    ADD COLUMN type_scores   JSONB,        -- {deviceType: points}; null on hosts classified before V60
    ADD COLUMN type_reasons  JSONB,        -- {deviceType: [reason, ...]}
    ADD COLUMN rule_votes    JSONB,        -- [{rule, deviceType, weight}] counted in type_scores
    -- The last time re-scoring changed the device type: when, from what, by whom, which rules.
    ADD COLUMN rescored_at   TIMESTAMP,
    ADD COLUMN rescored_from VARCHAR(100),
    ADD COLUMN rescored_by   VARCHAR(255),
    ADD COLUMN rescored_rules TEXT;

-- What a Re-apply run changed, listed in its result: [{fileId, ip, from, to, rules}] (capped).
ALTER TABLE rule_reapply_jobs
    ADD COLUMN reclassified_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN reclassified       JSONB,
    ADD COLUMN stale_labels_count INTEGER NOT NULL DEFAULT 0;
