-- ─────────────────────────────────────────────────────────────────────────────
-- Baseline schema — consolidated from V1–V32
-- ─────────────────────────────────────────────────────────────────────────────

-- Extensions
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ── Helper function ───────────────────────────────────────────────────────────
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- ── files ─────────────────────────────────────────────────────────────────────
CREATE TABLE files (
    id               UUID          PRIMARY KEY,
    file_name        VARCHAR(255)  NOT NULL,
    file_size        BIGINT        NOT NULL,
    file_hash        VARCHAR(64),
    minio_path       VARCHAR(512)  NOT NULL,
    uploaded_at      TIMESTAMP     NOT NULL,
    status           VARCHAR(50)   NOT NULL,
    packet_count     INTEGER,
    total_bytes      BIGINT,
    duration         BIGINT,
    start_time       TIMESTAMP,
    end_time         TIMESTAMP,
    enable_ndpi               BOOLEAN NOT NULL DEFAULT TRUE,
    enable_file_extraction    BOOLEAN NOT NULL DEFAULT TRUE,
    created_at       TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_files_status      ON files (status);
CREATE INDEX idx_files_uploaded_at ON files (uploaded_at DESC);
CREATE INDEX idx_files_file_name   ON files (file_name);
CREATE INDEX idx_files_file_hash   ON files (file_hash);

CREATE TRIGGER update_files_updated_at
    BEFORE UPDATE ON files
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ── analysis_results ─────────────────────────────────────────────────────────
CREATE TABLE analysis_results (
    id             UUID        PRIMARY KEY,
    file_id        UUID        NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    packet_count   BIGINT,
    total_bytes    BIGINT,
    start_time     TIMESTAMP,
    end_time       TIMESTAMP,
    duration_ms    BIGINT,
    protocol_stats JSONB,
    status         VARCHAR(50) NOT NULL DEFAULT 'pending',
    error_message  TEXT,
    created_at     TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_analysis_file_id ON analysis_results (file_id);
CREATE INDEX idx_analysis_status  ON analysis_results (status);

CREATE TRIGGER trigger_analysis_updated_at
    BEFORE UPDATE ON analysis_results
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ── conversations ─────────────────────────────────────────────────────────────
CREATE TABLE conversations (
    id                UUID          PRIMARY KEY,
    file_id           UUID          NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    src_ip            VARCHAR(45)   NOT NULL,
    src_port          INTEGER,
    dst_ip            VARCHAR(45)   NOT NULL,
    dst_port          INTEGER,
    protocol          VARCHAR(100)  NOT NULL,
    packet_count      BIGINT        NOT NULL DEFAULT 0,
    total_bytes       BIGINT        NOT NULL DEFAULT 0,
    start_time        TIMESTAMP     NOT NULL,
    end_time          TIMESTAMP     NOT NULL,
    app_name          VARCHAR(50),
    category          VARCHAR(50),
    hostname          VARCHAR(255),
    tshark_protocol   VARCHAR(50),
    ja3_client        VARCHAR(32),
    ja3_server        VARCHAR(32),
    tls_issuer        TEXT,
    tls_subject       TEXT,
    tls_not_before    TIMESTAMP,
    tls_not_after     TIMESTAMP,
    flow_risks        TEXT[]        DEFAULT '{}',
    custom_signatures TEXT[],
    http_user_agents  TEXT[],
    created_at        TIMESTAMP     NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_conv_file_id      ON conversations (file_id);
CREATE INDEX idx_conv_src_ip       ON conversations (src_ip);
CREATE INDEX idx_conv_dst_ip       ON conversations (dst_ip);
CREATE INDEX idx_conv_protocol     ON conversations (protocol);
CREATE INDEX idx_conv_app_name     ON conversations (file_id, app_name);
CREATE INDEX idx_conv_category     ON conversations (file_id, category);
CREATE INDEX idx_conv_start_time   ON conversations (file_id, start_time);
CREATE INDEX idx_conv_packet_count ON conversations (file_id, packet_count);
CREATE INDEX idx_conv_total_bytes  ON conversations (file_id, total_bytes);

CREATE INDEX idx_conv_src_ip_trgm  ON conversations USING gin (lower(src_ip)   gin_trgm_ops);
CREATE INDEX idx_conv_dst_ip_trgm  ON conversations USING gin (lower(dst_ip)   gin_trgm_ops);
CREATE INDEX idx_conv_hostname_trgm ON conversations USING gin (lower(hostname) gin_trgm_ops);

CREATE INDEX idx_conversations_custom_signatures ON conversations USING gin (custom_signatures);
CREATE INDEX idx_conversations_http_user_agents  ON conversations USING gin (http_user_agents);

-- ── packets ───────────────────────────────────────────────────────────────────
CREATE TABLE packets (
    id                  UUID        PRIMARY KEY,
    file_id             UUID        NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    conversation_id     UUID        REFERENCES conversations (id) ON DELETE CASCADE,
    packet_number       BIGINT      NOT NULL,
    timestamp           TIMESTAMP   NOT NULL,
    src_ip              VARCHAR(45) NOT NULL,
    src_port            INTEGER,
    dst_ip              VARCHAR(45) NOT NULL,
    dst_port            INTEGER,
    protocol            VARCHAR(100) NOT NULL,
    packet_size         INTEGER     NOT NULL,
    payload             TEXT,
    detected_file_type  VARCHAR(32),
    info                TEXT,
    created_at          TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_packet_file_id   ON packets (file_id);
CREATE INDEX idx_packet_conv_id   ON packets (conversation_id);
CREATE INDEX idx_packet_timestamp ON packets (timestamp);
CREATE INDEX idx_packet_number    ON packets (file_id, packet_number);

-- ── stories ───────────────────────────────────────────────────────────────────
CREATE TABLE stories (
    id            UUID         PRIMARY KEY,
    file_id       UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    generated_at  TIMESTAMP    NOT NULL,
    content       TEXT         NOT NULL,
    model_used    VARCHAR(100),
    tokens_used   INTEGER,
    status        VARCHAR(50)  NOT NULL,
    error_message TEXT,
    created_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_stories_file_id      ON stories (file_id);
CREATE INDEX idx_stories_generated_at ON stories (generated_at DESC);
CREATE INDEX idx_stories_status       ON stories (status);

-- ── host_classifications ──────────────────────────────────────────────────────
CREATE TABLE host_classifications (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id      UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    ip           VARCHAR(45)  NOT NULL,
    mac          VARCHAR(17),
    manufacturer VARCHAR(100),
    ttl          INTEGER,
    device_type  VARCHAR(50)  NOT NULL,
    confidence   INTEGER      NOT NULL,
    UNIQUE (file_id, ip)
);

-- ── ip_geo_cache ──────────────────────────────────────────────────────────────
CREATE TABLE ip_geo_cache (
    ip           VARCHAR(45)       PRIMARY KEY,
    country      VARCHAR(100),
    country_code VARCHAR(2),
    asn          VARCHAR(20),
    org          VARCHAR(255),
    region       VARCHAR(100),
    city         VARCHAR(100),
    lat          DOUBLE PRECISION,
    lon          DOUBLE PRECISION,
    looked_up_at TIMESTAMP         NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ── extracted_files ───────────────────────────────────────────────────────────
CREATE TABLE extracted_files (
    id                UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id           UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    conversation_id   UUID         REFERENCES conversations (id) ON DELETE SET NULL,
    filename          VARCHAR(500),
    mime_type         VARCHAR(200),
    file_size         BIGINT,
    sha256            VARCHAR(64),
    minio_path        VARCHAR(1000) NOT NULL,
    extraction_method VARCHAR(50),
    created_at        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_extracted_file_id              ON extracted_files (file_id);
CREATE INDEX idx_extracted_conv_id              ON extracted_files (conversation_id);
CREATE INDEX idx_extracted_files_file_id_sha256 ON extracted_files (file_id, sha256);

-- ── ip_org_rules ──────────────────────────────────────────────────────────────
CREATE TABLE ip_org_rules (
    id            BIGSERIAL    PRIMARY KEY,
    label         VARCHAR(255) NOT NULL,
    cidr          VARCHAR(50)  NOT NULL,
    prefix_length INT          NOT NULL,
    created_at    TIMESTAMP    NOT NULL DEFAULT NOW()
);
