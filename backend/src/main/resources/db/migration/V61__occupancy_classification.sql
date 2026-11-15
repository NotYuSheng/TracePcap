-- #918 item 3, slice 2: classify each device that held an address, not just the address.

-- Every TTL a source address sent with, and when, so each occupancy gets the TTL its own device
-- sent (a Windows laptop's 128, then a phone's 64) rather than the address's first-seen one.
CREATE TABLE host_ttl_windows (
    id         BIGSERIAL    PRIMARY KEY,
    file_id    UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    ip         VARCHAR(45)  NOT NULL,
    ttl        INT          NOT NULL,
    first_seen TIMESTAMP(3) NOT NULL,
    last_seen  TIMESTAMP(3) NOT NULL,
    packets    BIGINT       NOT NULL DEFAULT 0
);
CREATE INDEX host_ttl_windows_file_ip ON host_ttl_windows (file_id, ip);

-- Each occupancy's own classification, worked out from the traffic in its window. The address's
-- row in host_classifications stays as it was (every existing reader keeps working); occupancy
-- rows exist only for addresses that more than one device held.
ALTER TABLE ip_occupancies
    ADD COLUMN device_type        VARCHAR(50),
    ADD COLUMN confidence         INT,
    ADD COLUMN winner_score       INT,
    ADD COLUMN winner_reasons     TEXT,
    ADD COLUMN runner_up_type     VARCHAR(50),
    ADD COLUMN runner_up_score    INT,
    ADD COLUMN runner_up_reasons  TEXT,
    ADD COLUMN manufacturer       VARCHAR(255),
    ADD COLUMN ttl                INT,
    ADD COLUMN logged_in_user     VARCHAR(255),
    ADD COLUMN conversation_count BIGINT;
