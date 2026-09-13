-- ── Windows identity adjudication (#809, fixes the #808 CTF-demo gap) ────────
-- One adjudicated answer per (file, ip): a winner with confidence, or an explicitly contested
-- outcome listing the competing candidates. Human overrides (via the existing question-agnostic
-- human_overrides table, keyed by question='windows-identity') rank first; re-adjudication fires
-- on analysis completion, same as host_identities (V34), which this table mirrors.
--
-- Unlike host_identities, absence is meaningful: not every host has an observed Windows identity,
-- so a host with no Kerberos/LDAP claims gets no row here rather than a synthesized "unknown" one.

CREATE TABLE windows_identities (
    id            BIGSERIAL PRIMARY KEY,
    file_id       UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    ip            VARCHAR(45)  NOT NULL,
    primary_label VARCHAR(255) NOT NULL,  -- free-text username/display name, not a fixed enum
    basis         VARCHAR(20)  NOT NULL,  -- HUMAN | MACHINE
    confidence    INTEGER      NOT NULL,
    contested     BOOLEAN      NOT NULL DEFAULT FALSE,
    candidates    JSONB,                  -- [{label, source, score}] when contested/corroborated
    updated_at    TIMESTAMP    NOT NULL DEFAULT now(),
    CONSTRAINT uq_windows_identities UNIQUE (file_id, ip)
);
