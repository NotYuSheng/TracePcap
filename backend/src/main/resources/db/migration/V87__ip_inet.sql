-- #1354: CIDR membership in SQL for IPv4 and IPv6 alike, replacing ip_to_int (V27), which was
-- IPv4 arithmetic and so never put an IPv6 host in a subnet.
--
-- ip_inet(text) is the address a text column holds as inet, or NULL when it isn't an address
-- literal (a MAC endpoint, a name, garbage). Use it as:  ip_inet(ip) <<= CAST(? AS inet).
-- An inet of one family is never inside a CIDR of the other. It reads addresses as
-- Cidr.addressBytes does: a scope id (fe80::1%eth0) is dropped, and an IPv4-mapped address
-- (::ffff:10.0.0.1) is its IPv4 address.
--
-- A plain ::inet cast throws on a bad literal, so each form is checked by pattern first and cast
-- only when the cast can't fail: plain, inlinable SQL with no exception block (a subtransaction
-- per row) for IPv4 and for hex IPv6. Only an IPv6 address with a dotted IPv4 tail or a scope id,
-- which are rare, goes through the guarded cast.

-- An IPv4-mapped address as its IPv4 address; anything else unchanged.
CREATE OR REPLACE FUNCTION ip_unmap(a inet) RETURNS inet AS $$
    SELECT CASE WHEN family(a) = 6 AND a <<= '::ffff:0.0.0.0/96'::inet
                THEN '0.0.0.0'::inet + (a - '::ffff:0.0.0.0'::inet)
                ELSE a END
$$ LANGUAGE sql IMMUTABLE STRICT PARALLEL SAFE;

-- The guarded cast, for the rare IPv6 address with a dotted IPv4 tail or a scope id (dropped).
CREATE OR REPLACE FUNCTION ip_inet6(ip TEXT) RETURNS inet AS $$
BEGIN
    RETURN split_part(ip, '%', 1)::inet;
EXCEPTION WHEN invalid_text_representation THEN
    RETURN NULL;
END
$$ LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION ip_inet(ip TEXT) RETURNS inet AS $$
    SELECT ip_unmap(CASE
        WHEN ip ~ '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
             AND split_part(ip, '.', 1)::int <= 255
             AND split_part(ip, '.', 2)::int <= 255
             AND split_part(ip, '.', 3)::int <= 255
             AND split_part(ip, '.', 4)::int <= 255
        THEN ip::inet
        -- Every RFC 4291 text form without a dotted tail: eight groups, or fewer around one '::'.
        WHEN ip ~* ('^(([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}'
                   || '|([0-9a-f]{1,4}:){1,7}:'
                   || '|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}'
                   || '|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}'
                   || '|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}'
                   || '|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}'
                   || '|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}'
                   || '|[0-9a-f]{1,4}:(:[0-9a-f]{1,4}){1,6}'
                   || '|:((:[0-9a-f]{1,4}){1,7}|:))$')
        THEN ip::inet
        WHEN ip ~ '^[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*(%[^%]+)?$' AND ip ~ '[.%]'
        THEN ip_inet6(ip)
        ELSE NULL
    END)
$$ LANGUAGE sql IMMUTABLE PARALLEL SAFE;

DROP FUNCTION IF EXISTS ip_to_int(TEXT);
