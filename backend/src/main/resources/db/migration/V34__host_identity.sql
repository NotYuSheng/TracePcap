-- ── Host identity adjudication (#512 slice 5, fixes #499 / #498) ─────────────
-- One adjudicated answer per (file, ip): a winner with confidence, or an explicitly
-- CONTESTED outcome listing the competing candidates. Human-confirmed node-role labels
-- rank first; re-adjudication fires on analysis completion and on node-role changes.

-- Scan output must report its full result, not just the argmax: the runner-up lets the
-- adjudicator see how close second place was (a 1000-vs-70 walkover is invisible otherwise).
ALTER TABLE host_classifications
    ADD COLUMN winner_score    INTEGER,
    ADD COLUMN runner_up_type  VARCHAR(50),
    ADD COLUMN runner_up_score INTEGER;

CREATE TABLE host_identities (
    id            BIGSERIAL PRIMARY KEY,
    file_id       UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    ip            VARCHAR(45)  NOT NULL,
    primary_label VARCHAR(100) NOT NULL,
    basis         VARCHAR(20)  NOT NULL,  -- HUMAN | MACHINE
    confidence    INTEGER      NOT NULL,
    contested     BOOLEAN      NOT NULL DEFAULT FALSE,
    candidates    JSONB,                  -- [{label, source, score}] when contested
    updated_at    TIMESTAMP    NOT NULL DEFAULT now(),
    CONSTRAINT uq_host_identities UNIQUE (file_id, ip)
);
