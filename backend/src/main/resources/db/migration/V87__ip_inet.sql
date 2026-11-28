-- #1354: CIDR membership in SQL for IPv4 and IPv6 alike, replacing ip_to_int (V27), which was
-- IPv4 arithmetic and so never put an IPv6 host in a subnet.
--
-- ip_inet(text) is the address a text column holds as inet, or NULL when it isn't an address
-- literal (a MAC endpoint, a name, garbage). Use it as:  ip_inet(ip) <<= CAST(? AS inet).
-- An inet of one family is never inside a CIDR of the other.
--
-- A bad literal makes a plain ::inet cast throw, so the IPv6 path catches that. The IPv4 path is
-- checked by pattern and needs no exception block (a subtransaction per row), so the common case
-- stays a plain, inlinable SQL expression.
CREATE OR REPLACE FUNCTION ip_inet6(ip TEXT) RETURNS inet AS $$
BEGIN
    RETURN split_part(ip, '%', 1)::inet; -- drop a scope id (fe80::1%eth0)
EXCEPTION WHEN invalid_text_representation THEN
    RETURN NULL;
END
$$ LANGUAGE plpgsql IMMUTABLE STRICT PARALLEL SAFE;

CREATE OR REPLACE FUNCTION ip_inet(ip TEXT) RETURNS inet AS $$
    SELECT CASE
        WHEN ip ~ '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
             AND split_part(ip, '.', 1)::int <= 255
             AND split_part(ip, '.', 2)::int <= 255
             AND split_part(ip, '.', 3)::int <= 255
             AND split_part(ip, '.', 4)::int <= 255
        THEN ip::inet
        WHEN ip ~ '^[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(%[^%]+)?$'
        THEN ip_inet6(ip)
        ELSE NULL
    END
$$ LANGUAGE sql IMMUTABLE PARALLEL SAFE;

DROP FUNCTION IF EXISTS ip_to_int(TEXT);
