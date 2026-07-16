-- ── Hostname claims (#512 slice 4, prerequisite for #511) ────────────────────
-- Every hostname observation for an IP, with the source that asserted it — conflict-preserving.
-- The previous behaviour picked one winner by source priority at write time and discarded the
-- rest, which erased exactly the conflicts identity scanners need (a host DHCP-announcing another
-- machine's name was undetectable). Winner-picking now happens at read/adjudication time; these
-- rows are the REPORTED-grade facts it draws from. Re-analysis regenerates a file's claims.

CREATE TABLE hostname_claims (
    id          BIGSERIAL PRIMARY KEY,
    file_id     UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    ip          VARCHAR(45)  NOT NULL,
    hostname    VARCHAR(255) NOT NULL,
    source      VARCHAR(20)  NOT NULL,
    created_at  TIMESTAMP    NOT NULL DEFAULT now(),
    CONSTRAINT uq_hostname_claims UNIQUE (file_id, ip, hostname, source)
);
