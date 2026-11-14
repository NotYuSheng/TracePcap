-- #462 phase 1: which network a DHCP lease came from, from the server's ACK. Two networks that use
-- the same range (two sites, two VLANs) differ here even when every address is the same.
ALTER TABLE dhcp_leases
    ADD COLUMN server_mac    VARCHAR(50),
    ADD COLUMN server_id     VARCHAR(45),
    ADD COLUMN router        VARCHAR(45),
    ADD COLUMN domain        VARCHAR(255),
    ADD COLUMN lease_seconds BIGINT,
    ADD COLUMN subnet_mask   VARCHAR(45),
    ADD COLUMN vlan_id       INT;
