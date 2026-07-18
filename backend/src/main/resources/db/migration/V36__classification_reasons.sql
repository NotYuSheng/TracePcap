-- ── Classification reasons survive Scan → Adjudicate (adjudication explainability) ──
-- The ScoreBoard already records WHY each device type scored (a human-readable reason per
-- contributing signal), but those reasons were logged and dropped. Persisting them with the
-- winner and runner-up lets the adjudicator carry them out to the analyst: "why is this a
-- SERVER?" becomes answerable as the concrete list of signals that voted for it.
--
-- Stored newline-joined (reason strings may themselves contain commas), split back on read.
ALTER TABLE host_classifications
    ADD COLUMN winner_reasons   TEXT,
    ADD COLUMN runner_up_reasons TEXT;
