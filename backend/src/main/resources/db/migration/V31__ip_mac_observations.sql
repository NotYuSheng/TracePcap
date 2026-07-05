-- Distinct source MACs observed per IP within a single capture (#461). host_classifications is
-- unique on (file_id, ip) — one MAC per IP — so it cannot represent an IP claimed by two devices in
-- the same capture (overlapping networks, ARP conflict). This table keeps every distinct IP↔MAC
-- pairing seen so that "IP with >1 MAC in one file" can be detected as an overlap tell.
CREATE TABLE ip_mac_observations (
    id       BIGSERIAL   PRIMARY KEY,
    file_id  UUID        NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    ip       VARCHAR(45) NOT NULL,
    mac      VARCHAR(17) NOT NULL,
    UNIQUE (file_id, ip, mac)
);

CREATE INDEX idx_ip_mac_observations_file_ip ON ip_mac_observations (file_id, ip);
