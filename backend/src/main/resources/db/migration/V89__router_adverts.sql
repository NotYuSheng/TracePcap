-- #1357: IPv6 router advertisements, one row per router (MAC, link-local address, VLAN) a capture
-- holds. With DHCPv6 leases (stored in dhcp_leases) they tell the capture's IPv6 networks apart,
-- as DHCPv4 leases do for IPv4 (#462).
CREATE TABLE router_adverts (
    id         BIGSERIAL    PRIMARY KEY,
    file_id    UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    router_mac VARCHAR(50)  NOT NULL,
    router_ip  VARCHAR(45),
    vlan_id    INT,
    prefixes   TEXT[]       NOT NULL DEFAULT '{}',
    domain     VARCHAR(255),
    first_seen TIMESTAMP(3) NOT NULL,
    last_seen  TIMESTAMP(3) NOT NULL
);
CREATE INDEX idx_router_adverts_file ON router_adverts (file_id);
