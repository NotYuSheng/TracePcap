-- How many alerts Suricata logged on each conversation (#1284), next to how many records were kept.
-- ids_alerts keeps at most 100 records each way on a connection and 20,000 per capture; this says when a
-- conversation's records are only the first of them, so no count built on them reads as complete.
-- No foreign key to conversations, as for ids_alerts: written in its own transaction.
CREATE TABLE ids_alert_counts (
    conversation_id UUID PRIMARY KEY,
    file_id         UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    src_ip          VARCHAR(45),
    dst_ip          VARCHAR(45),
    total           INTEGER NOT NULL,
    kept            INTEGER NOT NULL
);
CREATE INDEX idx_ids_alert_counts_file ON ids_alert_counts (file_id);
