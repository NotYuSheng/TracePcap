-- #1351: subnet labels, custom ranges and organisation rules now save the network a CIDR names ("10.1.2.3/8" is
-- saved as "10.0.0.0/8"). Rewrite IPv4 rows saved before with host bits set, so a later save of
-- the same range finds them instead of adding a second entry. Matching already masked them, so
-- nothing classifies differently.
--
-- A row whose normalised form already exists in the same list is left as it was: the two can't
-- share a CIDR (the unique indexes), and choosing which to delete is the operator's call. IPv6
-- rows keep Java's long form, which Postgres' text output wouldn't match.

UPDATE subnet_definitions s
   SET cidr = host(network(s.cidr::inet)) || '/' || masklen(s.cidr::inet)
 WHERE s.cidr ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$'
   AND s.cidr <> host(network(s.cidr::inet)) || '/' || masklen(s.cidr::inet)
   AND NOT EXISTS (
       SELECT 1 FROM subnet_definitions o
        WHERE o.id <> s.id
          AND o.network_id IS NOT DISTINCT FROM s.network_id
          AND COALESCE(o.segment_key, '') = COALESCE(s.segment_key, '')
          AND o.cidr = host(network(s.cidr::inet)) || '/' || masklen(s.cidr::inet));

UPDATE custom_private_ranges r
   SET cidr = host(network(r.cidr::inet)) || '/' || masklen(r.cidr::inet)
 WHERE r.cidr ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$'
   AND r.cidr <> host(network(r.cidr::inet)) || '/' || masklen(r.cidr::inet)
   AND NOT EXISTS (
       SELECT 1 FROM custom_private_ranges o
        WHERE o.id <> r.id
          AND o.network_id IS NOT DISTINCT FROM r.network_id
          AND o.cidr = host(network(r.cidr::inet)) || '/' || masklen(r.cidr::inet));

-- Organisation rules too. Only network rows are unique on CIDR (V59), so a default row is
-- rewritten even when an equal default exists: duplicates there were already allowed.
UPDATE ip_org_rules r
   SET cidr = host(network(r.cidr::inet)) || '/' || masklen(r.cidr::inet)
 WHERE r.cidr ~ '^[0-9]{1,3}(\.[0-9]{1,3}){3}/[0-9]{1,2}$'
   AND r.cidr <> host(network(r.cidr::inet)) || '/' || masklen(r.cidr::inet)
   AND (r.network_id IS NULL OR NOT EXISTS (
       SELECT 1 FROM ip_org_rules o
        WHERE o.id <> r.id
          AND o.network_id = r.network_id
          AND o.cidr = host(network(r.cidr::inet)) || '/' || masklen(r.cidr::inet)));
