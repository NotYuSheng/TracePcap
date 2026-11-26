-- How complete a capture is (#1268): Suricata's own counters for the run, one row per file.
CREATE TABLE capture_stats (
    file_id              UUID PRIMARY KEY REFERENCES files(id) ON DELETE CASCADE,
    packets              BIGINT,
    invalid_packets      BIGINT,
    tcp_sessions         BIGINT,
    reassembly_gaps      BIGINT,
    stream_depth_reached BIGINT,
    memcap_drops         BIGINT,
    recorded_at          TIMESTAMP NOT NULL DEFAULT now()
);

-- Suricata's protocol anomalies (#1268): malformed or one-sided traffic, per conversation.
-- No foreign key to conversations, as for ids_alerts: written in its own transaction.
CREATE TABLE suricata_anomalies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id         UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    conversation_id UUID NOT NULL,
    anomaly_time    TIMESTAMP,
    src_ip          VARCHAR(45),
    dst_ip          VARCHAR(45),
    anomaly_type    VARCHAR(64),
    layer           VARCHAR(64),
    app_proto       VARCHAR(64),
    event           VARCHAR(255) NOT NULL
);
CREATE INDEX idx_suricata_anomalies_conversation ON suricata_anomalies (conversation_id);
CREATE INDEX idx_suricata_anomalies_file ON suricata_anomalies (file_id);
