-- Record which service roles each host was detected serving (#362 follow-up).
--
-- `service_roles` is a comma-joined list of roles a host acted as, e.g. "dns" (later "http-api").
-- It drives two things: the host's device classification (a DNS responder → DNS_SERVER) and the
-- per-role activity tabs shown in the network-diagram node modal. Null when the host serves none.
ALTER TABLE host_classifications
    ADD COLUMN service_roles TEXT;
