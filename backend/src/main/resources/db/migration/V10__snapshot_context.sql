-- ── Snapshot context & notes ──────────────────────────────────────────────────
-- Analyst-supplied context for each snapshot (e.g. "post-maintenance scan")
-- and optional operational notes. Both feed into per-snapshot LLM insights.

ALTER TABLE network_snapshots
    ADD COLUMN context TEXT,
    ADD COLUMN notes   TEXT;

-- ── snapshot_insights ─────────────────────────────────────────────────────────
-- LLM-generated insight reports scoped to a single snapshot.

CREATE TABLE snapshot_insights (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id     UUID         NOT NULL REFERENCES network_snapshots(id) ON DELETE CASCADE,
    generated_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    model_used      VARCHAR(100),
    status          VARCHAR(20)  NOT NULL DEFAULT 'COMPLETED',  -- COMPLETED | FAILED
    content         JSONB,
    error_message   TEXT
);

CREATE INDEX idx_snapshot_insights_snapshot ON snapshot_insights (snapshot_id, generated_at DESC);
