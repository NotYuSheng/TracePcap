-- ── entity_notes ──────────────────────────────────────────────────────────────
-- Stores user-written notes for IP addresses, devices (MAC), protocols, and
-- applications. Notes are global (not per-file) so they persist across captures.

CREATE TABLE entity_notes (
    id          BIGSERIAL    PRIMARY KEY,
    entity_type VARCHAR(20)  NOT NULL,  -- IP | DEVICE | PROTOCOL | APPLICATION
    entity_key  VARCHAR(255) NOT NULL,
    note        TEXT         NOT NULL,
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (entity_type, entity_key)
);

CREATE INDEX idx_entity_notes_lookup ON entity_notes (entity_type, entity_key);

CREATE TRIGGER update_entity_notes_updated_at
    BEFORE UPDATE ON entity_notes
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
