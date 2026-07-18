-- ── Generic human override for any adjudicated question (adjudication explainability) ──
-- One row = a human's final answer to one adjudicated question about one entity. Keyed by the
-- Adjudicator.question() string + (file, entity) so a NEW adjudicated question inherits override
-- with no new table: the adjudicator reads this by its own question key. Present ⇒ that IS the
-- answer — it outranks the machine vote (basis HUMAN, confidence 100, never contested).
--
-- Carries its own audit trail: who overrode and when. actor is written server-side from the
-- validated token (never client-supplied); "system" when auth is disabled.
CREATE TABLE human_overrides (
    id          BIGSERIAL   PRIMARY KEY,
    question    VARCHAR(64) NOT NULL,   -- Adjudicator.question(): "host-identity", "hostname", …
    file_id     UUID        NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    entity_key  VARCHAR(255) NOT NULL,  -- the host/IP/MAC this answer is about
    label       VARCHAR(100) NOT NULL,  -- the human's answer
    rationale   TEXT,                   -- why they overrode (optional, free text)
    actor       VARCHAR(255) NOT NULL,  -- who (audit); "system" when auth off
    created_at  TIMESTAMP   NOT NULL DEFAULT now(),
    updated_at  TIMESTAMP   NOT NULL DEFAULT now(),
    CONSTRAINT uq_human_override UNIQUE (question, file_id, entity_key)
);

CREATE INDEX idx_human_override_lookup ON human_overrides (question, file_id);
