-- The tickets and errors a domain controller returned (#1267), from Suricata's krb5 records: the
-- account and service of each, the error, and the ticket's encryption. Identical replies on one
-- conversation are one row with a count. No foreign key to conversations, as for ids_alerts.
CREATE TABLE kerberos_exchanges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id         UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    conversation_id UUID NOT NULL,
    first_time      TIMESTAMP,
    client_ip       VARCHAR(45) NOT NULL,
    kdc_ip          VARCHAR(45) NOT NULL,
    -- KRB_AS_REP, KRB_TGS_REP or KRB_ERROR
    msg_type        VARCHAR(32) NOT NULL,
    account         VARCHAR(255),
    service         VARCHAR(255),
    realm           VARCHAR(255),
    error_code      VARCHAR(64),
    encryption      VARCHAR(64),
    weak            BOOLEAN NOT NULL DEFAULT FALSE,
    op_count        INTEGER NOT NULL
);
CREATE INDEX idx_kerberos_exchanges_file ON kerberos_exchanges (file_id);
