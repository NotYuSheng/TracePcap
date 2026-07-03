-- ── node_roles → per-file / network-scoped (#369 redesign) ─────────────────────
-- Roles were global per (entity_type, entity_key), so a label was detached from any
-- pcap: applying one never re-classified anything and one baseline was shared across
-- every network the entity appeared in. Roles now live per FILE (a monitor snapshot
-- *is* a file). When a new snapshot is added the prior snapshot's classification is
-- carried forward and validated against the new pcap's observed properties, flagging
-- drift automatically at ingest. The "present-day" label is simply an entity's role
-- in the latest snapshot.
--
-- Existing global rows have no file to attribute them to and are dropped (the previous
-- shape shipped only on the unmerged feature branch).

DROP TRIGGER IF EXISTS update_node_roles_updated_at ON node_roles;
DROP TABLE IF EXISTS node_roles;

CREATE TABLE node_roles (
    id                  BIGSERIAL    PRIMARY KEY,
    file_id             UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    entity_type         VARCHAR(20)  NOT NULL,  -- IP | DEVICE
    entity_key          VARCHAR(255) NOT NULL,  -- IP address or MAC
    role_label          VARCHAR(100),
    role_description    TEXT,
    origin              VARCHAR(20)  NOT NULL DEFAULT 'MANUAL',  -- MANUAL | AI | CARRIED_FORWARD
    llm_suggested       BOOLEAN      NOT NULL DEFAULT FALSE,
    confirmed_by_human  BOOLEAN      NOT NULL DEFAULT FALSE,
    -- Snapshot of the node's key properties in THIS file (device type, MAC, dominant
    -- protocols, external orgs); the drift baseline carried into the next snapshot.
    observed_properties JSONB,
    -- Staleness: set when a carried-forward label drifts from its baseline at ingest.
    stale_since         TIMESTAMP,
    stale_fields        JSONB,
    created_at          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (file_id, entity_type, entity_key)
);

CREATE INDEX idx_node_roles_lookup ON node_roles (file_id, entity_type, entity_key);

CREATE TRIGGER update_node_roles_updated_at
    BEFORE UPDATE ON node_roles
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
