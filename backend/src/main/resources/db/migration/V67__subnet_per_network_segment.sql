-- #462 phase 2b: a monitored network's subnet label can be for one of several networks that share
-- a range (two sites both on 192.168.1.0/24), told apart by VLAN or DHCP server. The shared default
-- never has a segment: segments belong to a monitored network's captures.
ALTER TABLE subnet_definitions
    ADD COLUMN segment_key   VARCHAR(100),
    ADD COLUMN segment_label VARCHAR(255),
    ADD CONSTRAINT subnet_definitions_default_no_segment CHECK (network_id IS NOT NULL OR segment_key IS NULL);
DROP INDEX subnet_definitions_network_cidr;
CREATE UNIQUE INDEX subnet_definitions_network_cidr
    ON subnet_definitions (network_id, cidr, COALESCE(segment_key, '')) WHERE network_id IS NOT NULL;
