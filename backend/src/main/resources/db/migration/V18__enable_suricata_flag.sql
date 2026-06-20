-- Dedicated per-file toggle for Suricata IDS analysis (see #401).
--
-- Suricata is now gated by its own flag rather than reusing enable_ndpi, so users can run nDPI
-- protocol identification and Suricata signature-based detection independently. Existing rows
-- default to enabled, matching the prior behaviour where Suricata ran whenever nDPI was enabled.
ALTER TABLE files
    ADD COLUMN enable_suricata BOOLEAN NOT NULL DEFAULT TRUE;
