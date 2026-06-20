-- Store Suricata IDS alerts per conversation (see #401).
--
-- Suricata runs in offline pcap-read mode during Stage 3 enrichment (next to nDPI) and emits
-- signature-based threat alerts. Each alert is stored as a formatted string, mirroring the existing
-- flow_risks / custom_signatures text[] columns so the alerts surface in the same security view.
ALTER TABLE conversations
    ADD COLUMN suricata_alerts text[];
