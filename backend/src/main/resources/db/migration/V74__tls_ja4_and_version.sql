-- #599: two TLS facts per conversation.
--  * ja4_client: the JA4 client fingerprint. nDPI 6 reports JA4 (e.g. t13d1516h2_8daaf6152771_02713d6af862)
--    where nDPI 5 reported JA3C, which is why ja3_client stopped being filled; JA3 now comes from
--    Suricata's TLS records instead.
--  * tls_version: the negotiated version, from Suricata (e.g. "TLS 1.2"), so legacy TLS is visible.
ALTER TABLE conversations ADD COLUMN ja4_client VARCHAR(36);
ALTER TABLE conversations ADD COLUMN tls_version VARCHAR(16);
