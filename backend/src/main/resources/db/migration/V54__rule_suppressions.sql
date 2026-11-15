-- Suppression (#925 phase 4): a network can switch a global rule off within its own views. The
-- rule keeps running everywhere else, and its matches stay stored; they're just not shown when a
-- capture is viewed in this network. Audited.
CREATE TABLE rule_suppressions (
    network_id  UUID         NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    rule_id     UUID         NOT NULL REFERENCES detection_rules (id) ON DELETE CASCADE,
    created_at  TIMESTAMP    NOT NULL DEFAULT now(),
    created_by  VARCHAR(255) NOT NULL,
    PRIMARY KEY (network_id, rule_id)
);
