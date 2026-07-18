-- ── Audit trail: who confirmed a node-role label (adjudication explainability) ──
-- confirmed_by_human was an anonymous boolean — it recorded THAT a human confirmed, never WHO.
-- With auth in play (Keycloak JWT), a human annotation should carry its author. Nullable: existing
-- rows and AI/carried-forward rows have no confirming human. Populated server-side from the
-- validated token (preferred_username), or "system" when auth is disabled.
ALTER TABLE node_roles
    ADD COLUMN confirmed_by VARCHAR(255);
