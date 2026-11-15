-- Clients that asked for an address (DHCP DISCOVER or REQUEST) and were never answered. They have
-- no address, so they aren't leases; their MAC, the name they asked under and the VLAN they asked
-- on are what tell them apart, and the VLAN is what places them in a network.
CREATE TABLE dhcp_unanswered_clients (
    id           BIGSERIAL    PRIMARY KEY,
    file_id      UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    mac          VARCHAR(50)  NOT NULL,
    hostname     VARCHAR(255),
    vendor_class VARCHAR(255),
    vlan_id      INTEGER,
    requests     INTEGER      NOT NULL,
    first_seen   TIMESTAMP(3) NOT NULL,
    last_seen    TIMESTAMP(3) NOT NULL,
    UNIQUE (file_id, mac)
);
