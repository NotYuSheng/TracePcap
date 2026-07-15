-- ── Extraction run manifest (#512 slice 2, fixes #501) ───────────────────────
-- Records, per file and per extractor, whether the extractor COMPLETED, FAILED,
-- or was SKIPPED — so downstream scanners can distinguish "the tool didn't run"
-- from "the tool ran and found nothing". Files analysed before this migration
-- have no rows; consumers must treat an absent row as unknown provenance.

CREATE TABLE extraction_runs (
    id          BIGSERIAL PRIMARY KEY,
    file_id     UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    extractor   VARCHAR(50)  NOT NULL,
    version     VARCHAR(20)  NOT NULL DEFAULT '1',
    status      VARCHAR(20)  NOT NULL,
    detail      TEXT,
    created_at  TIMESTAMP    NOT NULL DEFAULT now(),
    CONSTRAINT uq_extraction_runs_file_extractor UNIQUE (file_id, extractor)
);

CREATE INDEX idx_extraction_runs_file ON extraction_runs (file_id);
