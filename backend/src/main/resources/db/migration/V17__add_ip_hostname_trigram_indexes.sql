-- Enable pg_trgm for GIN-accelerated LIKE/ILIKE searches on IP and hostname columns.
-- These indexes are used by the IP/hostname contains-filter in the conversations listing.
CREATE EXTENSION IF NOT EXISTS pg_trgm;

CREATE INDEX IF NOT EXISTS idx_conv_src_ip_trgm
    ON conversations USING gin (lower(src_ip) gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_conv_dst_ip_trgm
    ON conversations USING gin (lower(dst_ip) gin_trgm_ops);

CREATE INDEX IF NOT EXISTS idx_conv_hostname_trgm
    ON conversations USING gin (lower(hostname) gin_trgm_ops);
