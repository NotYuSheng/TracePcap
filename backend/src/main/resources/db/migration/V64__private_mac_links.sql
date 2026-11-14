-- #918 slice 4b: recognising a phone across its private MACs.

-- A client's DHCP fingerprint: the options it asked for, in order (option 55), and its vendor class
-- (option 60). It names the OS, often the model, and stays the same when the MAC changes.
ALTER TABLE dhcp_leases
    ADD COLUMN fingerprint  VARCHAR(255),
    ADD COLUMN vendor_class VARCHAR(255);

-- An analyst's decision that two MACs in a monitored network are one device (same) or not
-- (not_same). Suggestions are worked out at read time; only decisions are stored. mac_a < mac_b.
CREATE TABLE device_links (
    id         BIGSERIAL    PRIMARY KEY,
    network_id UUID         NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    mac_a      VARCHAR(50)  NOT NULL,
    mac_b      VARCHAR(50)  NOT NULL,
    decision   VARCHAR(10)  NOT NULL CHECK (decision IN ('same', 'not_same')),
    reason     TEXT         NOT NULL,
    actor      VARCHAR(255),
    created_at TIMESTAMP    NOT NULL DEFAULT now(),
    CHECK (mac_a < mac_b),
    UNIQUE (network_id, mac_a, mac_b)
);
