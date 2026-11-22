-- #1233: how each TCP connection went, read from its handshake while parsing.
--   ANSWERED  the server replied (SYN+ACK, or traffic only an open connection carries)
--   NO_ANSWER SYNs went out and nothing came back
--   REJECTED  the server refused it with a reset
--   NULL      unknown: not TCP, or the capture joined after the SYN
-- Captures analysed before this have NULL until re-analysed.
ALTER TABLE conversations ADD COLUMN connection_outcome VARCHAR(16);
CREATE INDEX idx_conversations_file_outcome ON conversations (file_id, connection_outcome)
    WHERE connection_outcome IS NOT NULL;
