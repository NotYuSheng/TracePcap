-- What one host did to another over SMB and RPC (#1266), from Suricata's smb, dcerpc and SMB
-- fileinfo records: shares connected, files and pipes opened, files copied, RPC calls made.
-- Identical operations on one conversation are one row with a count.
-- No foreign key to conversations, as for ids_alerts: written in its own transaction.
CREATE TABLE remote_operations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id         UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    conversation_id UUID NOT NULL,
    first_time      TIMESTAMP,
    client_ip       VARCHAR(45) NOT NULL,
    server_ip       VARCHAR(45) NOT NULL,
    -- share | open | write | read | rpc
    kind            VARCHAR(16) NOT NULL,
    share           VARCHAR(1024),
    path            VARCHAR(1024),
    interface_uuid  VARCHAR(36),
    opnum           INTEGER,
    bytes           BIGINT,
    -- SMB's error, e.g. STATUS_ACCESS_DENIED; null when it succeeded
    status          VARCHAR(64),
    op_count        INTEGER NOT NULL
);
CREATE INDEX idx_remote_operations_file ON remote_operations (file_id);
CREATE INDEX idx_remote_operations_conversation ON remote_operations (conversation_id);
