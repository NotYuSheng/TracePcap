-- Host identity checks (#918 items 1c and 2).
--   ttls: every TTL seen from the IP (up to 16), not just the first, so a conflict is visible.
--   address_kind: VIRTUAL_FAILOVER for a VRRP/HSRP/CARP virtual address shared by routers; null
--     for an ordinary host.
--   identity_warning: why this "host" may be more than one machine (different TTL families,
--     several DHCP hostnames), in words the UI shows; null when nothing conflicts.
ALTER TABLE host_classifications
    ADD COLUMN ttls INTEGER[],
    ADD COLUMN address_kind VARCHAR(40),
    ADD COLUMN identity_warning TEXT;
