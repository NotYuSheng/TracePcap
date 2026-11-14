-- #462 phase 2a: which machine (or, for outside traffic, which site's router) each side of a
-- conversation was, so an address used on two networks can be told apart per conversation.
ALTER TABLE conversations
    ADD COLUMN src_mac VARCHAR(50),
    ADD COLUMN dst_mac VARCHAR(50);

-- TTLs per sending MAC too, so each network's machine on a shared address gets its own.
ALTER TABLE host_ttl_windows
    ADD COLUMN mac VARCHAR(50);

-- Each occupancy's own key (#462): the bare IP for an address's first device, ip@<start> for a
-- later one in time, ip~<network> for one on another network that shares the range.
ALTER TABLE ip_occupancies
    ADD COLUMN device_key VARCHAR(255);
