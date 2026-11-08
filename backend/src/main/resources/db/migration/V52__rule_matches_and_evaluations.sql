-- Detection rule sync (#925 phase 2). Matches are derived data: recomputed, never silently stale.
--
-- rule_matches: which conversation each rule matched. The source of truth for matches;
-- conversations.custom_signatures stays as the read model every view and filter uses, and is
-- recomputed from rule_matches joined to the enabled rules whenever either changes. Disabling,
-- renaming or deleting a rule therefore shows at once.
CREATE TABLE rule_matches (
    rule_id          UUID NOT NULL REFERENCES detection_rules (id) ON DELETE CASCADE,
    file_id          UUID NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    conversation_id  UUID NOT NULL REFERENCES conversations (id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, conversation_id)
);
CREATE INDEX idx_rule_matches_file ON rule_matches (file_id);

-- rule_evaluations: the last time a rule was checked against a capture, at which rule version,
-- and how it went. A capture is stale for a rule when there's no row, or the rule's version has
-- moved on. UNCHECKABLE: a payload rule that couldn't be re-checked because retention deleted the
-- capture's packets; its old matches are dropped rather than shown as if current.
CREATE TABLE rule_evaluations (
    rule_id       UUID        NOT NULL REFERENCES detection_rules (id) ON DELETE CASCADE,
    file_id       UUID        NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    rule_version  INTEGER     NOT NULL,
    result        VARCHAR(20) NOT NULL CHECK (result IN ('CHECKED', 'UNCHECKABLE')),
    match_count   INTEGER     NOT NULL DEFAULT 0,
    evaluated_at  TIMESTAMP   NOT NULL,
    PRIMARY KEY (rule_id, file_id)
);
CREATE INDEX idx_rule_evaluations_file ON rule_evaluations (file_id);

-- Re-apply runs in the background, one capture per transaction; this row is its progress.
CREATE TABLE rule_reapply_jobs (
    id            UUID         PRIMARY KEY,
    file_id       UUID         REFERENCES files (id) ON DELETE SET NULL,
    status        VARCHAR(20)  NOT NULL CHECK (status IN ('RUNNING', 'DONE', 'FAILED', 'INTERRUPTED')),
    total         INTEGER      NOT NULL DEFAULT 0,
    done          INTEGER      NOT NULL DEFAULT 0,
    failed        INTEGER      NOT NULL DEFAULT 0,
    error         TEXT,
    requested_by  VARCHAR(255) NOT NULL,
    created_at    TIMESTAMP    NOT NULL,
    finished_at   TIMESTAMP
);
CREATE INDEX idx_rule_reapply_jobs_created ON rule_reapply_jobs (created_at DESC);

-- Matches from before this version only exist as names in custom_signatures. Link the ones that
-- name a current global rule, so disabling or deleting that rule hides them too. No evaluations
-- are invented for them: which rule version produced them isn't known, so those captures show as
-- not yet checked against the current rules until someone re-applies.
INSERT INTO rule_matches (rule_id, file_id, conversation_id)
SELECT r.id, c.file_id, c.id
FROM conversations c
CROSS JOIN LATERAL unnest(c.custom_signatures) AS s(name)
JOIN detection_rules r ON r.scope = 'GLOBAL' AND lower(r.name) = lower(s.name)
ON CONFLICT DO NOTHING;
