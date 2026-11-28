-- #1357: Suricata writes IPv6 in full ("fd00:0000:0000:0000:0000:0000:0000:0010"), tshark
-- compressed ("fd00::10"). Alerts are matched to conversations and hosts by address text, so rows
-- saved before SuricataService.eveAddress never matched. Rewrite them as a save writes now.
--
-- Only Suricata's exact full form (eight 4-hex groups) is touched, so the cast can't fail. host()
-- writes RFC 5952, and an IPv4-mapped address as ::ffff:10.0.0.1, as tshark and eveAddress do.
UPDATE ids_alerts SET src_ip = host(src_ip::inet) WHERE src_ip ~* '^([0-9a-f]{4}:){7}[0-9a-f]{4}$';
UPDATE ids_alerts SET dst_ip = host(dst_ip::inet) WHERE dst_ip ~* '^([0-9a-f]{4}:){7}[0-9a-f]{4}$';
UPDATE ids_alert_counts SET src_ip = host(src_ip::inet) WHERE src_ip ~* '^([0-9a-f]{4}:){7}[0-9a-f]{4}$';
UPDATE ids_alert_counts SET dst_ip = host(dst_ip::inet) WHERE dst_ip ~* '^([0-9a-f]{4}:){7}[0-9a-f]{4}$';
UPDATE suricata_anomalies SET src_ip = host(src_ip::inet) WHERE src_ip ~* '^([0-9a-f]{4}:){7}[0-9a-f]{4}$';
UPDATE suricata_anomalies SET dst_ip = host(dst_ip::inet) WHERE dst_ip ~* '^([0-9a-f]{4}:){7}[0-9a-f]{4}$';
