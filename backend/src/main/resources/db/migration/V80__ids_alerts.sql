-- Every Suricata alert as Suricata logged it (#1265): the request that fired it, when, which side
-- sent it, and the rule's own metadata. conversations.suricata_alerts keeps the deduplicated
-- "message (sid sev)" strings the filters and the knowledge layer already read.
CREATE TABLE ids_alerts (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id            UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    -- No foreign key: written in its own transaction while the conversation rows may not be
    -- committed yet. Rows go with their file.
    conversation_id    UUID NOT NULL,
    alert_time         TIMESTAMP,
    src_ip             VARCHAR(45),
    src_port           INTEGER,
    dst_ip             VARCHAR(45),
    dst_port           INTEGER,
    sid                BIGINT NOT NULL,
    gid                INTEGER,
    rev                INTEGER,
    signature          TEXT NOT NULL,
    category           VARCHAR(255),
    severity           INTEGER,
    signature_severity VARCHAR(64),
    confidence         VARCHAR(64),
    attack_target      VARCHAR(255),
    metadata           JSONB,
    http_method        VARCHAR(32),
    http_host          VARCHAR(512),
    http_url           TEXT,
    http_user_agent    TEXT,
    http_status        INTEGER
);
CREATE INDEX idx_ids_alerts_conversation ON ids_alerts (conversation_id, alert_time);
CREATE INDEX idx_ids_alerts_file ON ids_alerts (file_id);
