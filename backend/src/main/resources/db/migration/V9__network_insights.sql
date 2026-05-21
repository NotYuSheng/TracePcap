-- ── node_roles ────────────────────────────────────────────────────────────────
-- Stores user-defined (or LLM-suggested) operational role labels for IP
-- addresses and devices (MAC). Global — not per-file.

CREATE TABLE node_roles (
    id                  BIGSERIAL    PRIMARY KEY,
    entity_type         VARCHAR(20)  NOT NULL,  -- IP | DEVICE
    entity_key          VARCHAR(255) NOT NULL,  -- IP address or MAC
    role_label          VARCHAR(100),
    role_description    TEXT,
    llm_suggested       BOOLEAN      NOT NULL DEFAULT FALSE,
    confirmed_by_human  BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (entity_type, entity_key)
);

CREATE INDEX idx_node_roles_lookup ON node_roles (entity_type, entity_key);

CREATE TRIGGER update_node_roles_updated_at
    BEFORE UPDATE ON node_roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ── network_external_events ───────────────────────────────────────────────────
-- Analyst-entered external events (e.g. "Water festival begins") that can be
-- correlated with observed network changes during LLM insight generation.

CREATE TABLE network_external_events (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id  UUID         NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    event_time  TIMESTAMP    NOT NULL,
    title       VARCHAR(255) NOT NULL,
    description TEXT,
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ext_events_network ON network_external_events (network_id, event_time DESC);

-- ── network_insights ──────────────────────────────────────────────────────────
-- LLM-generated insight reports for a network. Stores the latest structured
-- analysis (narrative, anomalies, correlations, recommendations).

CREATE TABLE network_insights (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id      UUID         NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    generated_at    TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    model_used      VARCHAR(100),
    status          VARCHAR(20)  NOT NULL DEFAULT 'COMPLETED',  -- COMPLETED | FAILED
    content         JSONB,
    error_message   TEXT
);

CREATE INDEX idx_network_insights_network ON network_insights (network_id, generated_at DESC);

-- ── network_annotations ───────────────────────────────────────────────────────
-- Free-text analyst annotations per network, optionally tied to a snapshot.
-- These feed into the next LLM insight generation as prior analyst context.

CREATE TABLE network_annotations (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id  UUID         NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    snapshot_id UUID         REFERENCES network_snapshots(id) ON DELETE SET NULL,
    body        TEXT         NOT NULL,
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_network_annotations_network ON network_annotations (network_id, created_at DESC);

CREATE TRIGGER update_network_annotations_updated_at
    BEFORE UPDATE ON network_annotations
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
