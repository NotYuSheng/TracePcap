-- ── Windows identity claims (#809) ────────────────────────────────────────────
-- Every Windows-identity observation for an IP, with the signal that asserted it — conflict-
-- preserving, same discipline as hostname_claims (V33). A username from Kerberos AS-REQ or an LDAP
-- searchRequest DN is testimony, not a measurement to pick a winner for at write time; winner-
-- picking happens at adjudication (see WindowsIdentityService). Re-analysis regenerates a file's
-- claims.

CREATE TABLE windows_identity_claims (
    id          BIGSERIAL PRIMARY KEY,
    file_id     UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    ip          VARCHAR(45)  NOT NULL,
    username    VARCHAR(255) NOT NULL,
    source      VARCHAR(20)  NOT NULL,
    created_at  TIMESTAMP    NOT NULL DEFAULT now(),
    CONSTRAINT uq_windows_identity_claims UNIQUE (file_id, ip, username, source)
);
