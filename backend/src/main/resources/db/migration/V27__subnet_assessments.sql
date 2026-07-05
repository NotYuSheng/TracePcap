-- Convert a dotted-quad IPv4 string to its 32-bit integer value, for range/CIDR membership tests.
-- Returns NULL for anything that isn't a well-formed IPv4 literal (e.g. IPv6, hostnames), so callers
-- must guard with a format check or treat NULL as "not in range". Used by the subnet label-suggestion
-- feature (#363) to find the member hosts of a CIDR.
CREATE OR REPLACE FUNCTION ip_to_int(ip TEXT) RETURNS BIGINT AS $$
    SELECT CASE
        WHEN ip ~ '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
             AND split_part(ip, '.', 1)::int <= 255
             AND split_part(ip, '.', 2)::int <= 255
             AND split_part(ip, '.', 3)::int <= 255
             AND split_part(ip, '.', 4)::int <= 255
        THEN split_part(ip, '.', 1)::bigint * 16777216
           + split_part(ip, '.', 2)::bigint * 65536
           + split_part(ip, '.', 3)::bigint * 256
           + split_part(ip, '.', 4)::bigint
        ELSE NULL
    END
$$ LANGUAGE sql IMMUTABLE;
