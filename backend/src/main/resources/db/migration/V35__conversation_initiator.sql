-- #496: record which endpoint opened a TCP connection.
--
-- Conversation keys are normalised so that A->B and B->A share one row, which means src_ip is
-- "whichever endpoint sorted first", not "who started it". Direction was never persisted at all —
-- which is why the frontend guessed a host's role from port numbers, and why a server listening on
-- a high port (:4434) was presented as a client.
--
-- The initiator is MEASURED: the traffic exhibited it (SYN without ACK). Nothing asserted it and no
-- tool judged it, which is precisely why it should replace a port-number heuristic.
--
-- Nullable, and NULL means UNKNOWN rather than "nobody initiated": UDP, ICMP and ARP have no
-- handshake, and a capture can begin mid-flow and miss the SYN. Existing rows stay NULL — they were
-- parsed before this field existed, and inventing an initiator for them from ports would be the bug
-- this column exists to remove.
ALTER TABLE conversations
    ADD COLUMN initiator_ip   VARCHAR(45),
    ADD COLUMN initiator_port INTEGER;

COMMENT ON COLUMN conversations.initiator_ip IS
    'IP that sent SYN without ACK — the endpoint that opened the connection. NULL when unknown '
    '(no handshake in this protocol, or the capture missed it). MEASURED.';

COMMENT ON COLUMN conversations.initiator_port IS
    'Port the initiator opened the connection from. NULL when initiator_ip is NULL.';
