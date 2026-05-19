-- ─────────────────────────────────────────────────────────────────────────────
-- Network Monitor — named networks, PCAP snapshots, baseline definitions,
-- and change-detection events.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── networks ──────────────────────────────────────────────────────────────────
-- A named group of PCAPs that represent the same physical/logical network over
-- time (e.g. "Office LAN", "OT Segment A").
CREATE TABLE networks (
    id          UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_networks_name ON networks (name);

CREATE TRIGGER update_networks_updated_at
    BEFORE UPDATE ON networks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- ── network_snapshots ─────────────────────────────────────────────────────────
-- Links an existing uploaded PCAP (files table) to a Network.
-- snapshot_order is 0-based and recomputed from file.start_time after every
-- add/remove so that the timeline always reflects true capture chronology.
CREATE TABLE network_snapshots (
    id             UUID      PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id     UUID      NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    file_id        UUID      NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    snapshot_order INTEGER   NOT NULL DEFAULT 0,
    is_baseline    BOOLEAN   NOT NULL DEFAULT FALSE,
    added_at       TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (network_id, file_id)   -- one PCAP can only appear once per network
);

CREATE INDEX idx_ns_network_id ON network_snapshots (network_id);
CREATE INDEX idx_ns_file_id    ON network_snapshots (file_id);
CREATE INDEX idx_ns_order      ON network_snapshots (network_id, snapshot_order);

-- ── baseline_definitions ──────────────────────────────────────────────────────
-- Manual/explicit baseline entries: what devices, protocols, gateway, etc.
-- are *expected* in this network. Supplements or replaces the auto-inferred
-- baseline (first snapshot).
--
-- entry_type values:
--   DEVICE          – known MAC address (entityKey = MAC, entityValue = expected IP or null)
--   IP_MAC_BINDING  – expected (IP ↔ MAC) pair (entityKey = IP, entityValue = MAC)
--   GATEWAY         – expected gateway IP (entityKey = IP)
--   PROTOCOL        – expected L7 protocol (entityKey = tsharkProtocol name)
--   APP             – expected application (entityKey = appName)
--   VPN_FINGERPRINT – expected VPN risk token (entityKey = nDPI risk string)
CREATE TABLE baseline_definitions (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id   UUID         NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    entry_type   VARCHAR(50)  NOT NULL,
    entity_key   VARCHAR(255) NOT NULL,
    entity_value VARCHAR(255),
    notes        TEXT,
    created_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_bd_network_id ON baseline_definitions (network_id);
CREATE INDEX idx_bd_type       ON baseline_definitions (network_id, entry_type);

-- ── network_change_events ─────────────────────────────────────────────────────
-- One row per detected change between two consecutive snapshots (or vs. a
-- manual baseline). Generated automatically when a snapshot is added or the
-- baseline is changed.
--
-- change_type values:
--   MAC_ADDED, MAC_REMOVED      – device appeared / disappeared (by MAC)
--   IP_MAC_DRIFT                – same MAC got new IP, or same IP got new MAC
--   ASN_CHANGE                  – a new or lost ISP/ASN on external traffic
--   GATEWAY_CHANGE              – top external IP changed (gateway heuristic)
--   PROTOCOL_ADDED, PROTOCOL_REMOVED – L7 protocol appeared / disappeared
--   APP_ADDED, APP_REMOVED      – application appeared / disappeared
--   VPN_DRIFT                   – VPN risk token appeared / disappeared
--
-- severity values: INFO | WARNING | CRITICAL
CREATE TABLE network_change_events (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    network_id       UUID        NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    from_snapshot_id UUID        REFERENCES network_snapshots (id) ON DELETE SET NULL,
    to_snapshot_id   UUID        NOT NULL REFERENCES network_snapshots (id) ON DELETE CASCADE,
    change_type      VARCHAR(50) NOT NULL,
    entity_type      VARCHAR(50) NOT NULL,
    entity_key       VARCHAR(255) NOT NULL,
    old_value        JSONB,
    new_value        JSONB,
    severity         VARCHAR(20) NOT NULL DEFAULT 'INFO',
    detected_at      TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_nce_network_id  ON network_change_events (network_id);
CREATE INDEX idx_nce_to_snapshot ON network_change_events (to_snapshot_id);
CREATE INDEX idx_nce_type        ON network_change_events (network_id, change_type);
CREATE INDEX idx_nce_severity    ON network_change_events (network_id, severity);
CREATE INDEX idx_nce_detected_at ON network_change_events (network_id, detected_at DESC);
