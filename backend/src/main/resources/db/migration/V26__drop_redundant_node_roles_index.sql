-- Drop the redundant lookup index (#369 review). The UNIQUE (file_id, entity_type, entity_key)
-- constraint from V25 already backs an index on exactly those columns in the same order, so
-- idx_node_roles_lookup duplicated it — wasting space and slowing writes with no read benefit.
DROP INDEX IF EXISTS idx_node_roles_lookup;
