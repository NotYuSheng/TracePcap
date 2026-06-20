-- Surface passively-observed client hostnames in the Network Intelligence view (#368).
-- `hostname`        — the discovered name for the host (e.g. "Johns-MacBook.local", "DESKTOP-AB12").
-- `hostname_source` — how it was discovered, one of:
--                     reverse_dns, mdns, nbns, dhcp, manual.
ALTER TABLE host_classifications
    ADD COLUMN hostname        VARCHAR(255),
    ADD COLUMN hostname_source VARCHAR(20);
