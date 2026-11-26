-- The transport each conversation is keyed on (TCP, UDP, or the protocol for portless traffic), kept
-- apart from its display label (protocol: "TLSV1.2"). Flow records from nDPI, tshark and Suricata
-- are matched by it, and a detection rule's "protocol" means it. NULL for captures analysed before.
ALTER TABLE conversations ADD COLUMN transport VARCHAR(20);
