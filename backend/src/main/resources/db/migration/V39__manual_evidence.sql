-- ── Analyst-appended evidence for any adjudicated question (adjudication explainability) ──
-- Append-only: an analyst contributes a weighted signal toward a candidate ("this box is a domain
-- controller — I confirmed it out-of-band"). It re-enters the adjudication vote as one more weighted
-- input and shows in the reasons trail tagged analyst-provided — it does NOT silently become the
-- answer (only an explicit human_override short-circuits the machine). Keyed by the same
-- (question, file, entity) tuple as overrides, so a new adjudicated question inherits evidence too.
--
-- Carries its own audit trail: who added it and when (actor written server-side from the token).
CREATE TABLE manual_evidence (
    id          BIGSERIAL   PRIMARY KEY,
    question    VARCHAR(64) NOT NULL,   -- Adjudicator.question()
    file_id     UUID        NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    entity_key  VARCHAR(255) NOT NULL,
    label       VARCHAR(100) NOT NULL,  -- which candidate this evidence supports
    weight      INTEGER     NOT NULL,   -- how strongly (bounded in the service)
    reason      TEXT        NOT NULL,   -- shown verbatim in the reasons trail
    actor       VARCHAR(255) NOT NULL,  -- who (audit)
    created_at  TIMESTAMP   NOT NULL DEFAULT now()
);

CREATE INDEX idx_manual_evidence_lookup ON manual_evidence (question, file_id);
