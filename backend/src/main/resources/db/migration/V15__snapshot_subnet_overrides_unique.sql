-- Remove any duplicate (snapshot_id, cidr) rows that may exist before adding the constraint,
-- keeping the row with the smallest id in each duplicate group.
WITH ranked AS (
  SELECT id,
         ROW_NUMBER() OVER (
           PARTITION BY snapshot_id, cidr
           ORDER BY id
         ) AS rn
  FROM snapshot_subnet_overrides
)
DELETE FROM snapshot_subnet_overrides s
USING ranked r
WHERE s.id = r.id
  AND r.rn > 1;

ALTER TABLE snapshot_subnet_overrides
    ADD CONSTRAINT uq_snapshot_subnet_overrides_snapshot_cidr UNIQUE (snapshot_id, cidr);
