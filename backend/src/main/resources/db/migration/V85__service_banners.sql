-- What each server said about itself on the wire (investigation framework phase 4): SSH, FTP, HTTP,
-- SMB and MySQL banners, the SSH server's HASSH, and the initial TTL of its SYN-ACKs. Read against
-- the bundled honeypot signatures; identical values from one server and port are one row with a count.
CREATE TABLE service_banners (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id    UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    server_ip  VARCHAR(45) NOT NULL,
    port       INTEGER NOT NULL,
    -- ssh-banner, ssh-hassh, ftp-banner, http-server, smb-os, smb-server-name, mysql-version, ttl
    kind       VARCHAR(32) NOT NULL,
    value      VARCHAR(255) NOT NULL,
    seen_count INTEGER NOT NULL
);
CREATE INDEX idx_service_banners_file ON service_banners (file_id);
