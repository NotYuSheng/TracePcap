-- Distinct source MACs observed per IP within a single capture (#461). host_classifications is
-- unique on (file_id, ip) — one MAC per IP — so it cannot represent an IP claimed by two devices in
-- the same capture (overlapping networks, ARP conflict). This table keeps every distinct IP↔MAC
-- pairing seen so that "IP with >1 MAC in one file" can be detected as an overlap tell.
CREATE TABLE ip_mac_observations (
    id       BIGSERIAL   PRIMARY KEY,
    file_id  UUID        NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    ip       VARCHAR(45) NOT NULL,
    -- 50 (not 17) to tolerate EUI-64 (23 chars) and any malformed MAC without a DataIntegrityViolation.
    mac      VARCHAR(50) NOT NULL,
    UNIQUE (file_id, ip, mac)
);

-- No separate (file_id, ip) index: the UNIQUE (file_id, ip, mac) constraint's implicit B-tree already
-- serves prefix lookups on file_id and (file_id, ip), so a dedicated index would only add write cost.
