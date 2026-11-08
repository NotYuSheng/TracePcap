-- One stored capture per content hash, enforced by the database rather than by a check-then-insert
-- in FileServiceImpl (which let 8 simultaneous identical uploads through as 8 rows).
--
-- Existing duplicates can't simply be deleted: each one is a user's file with its own analysis.
-- Instead, keep the hash on the newest row per hash (the one duplicate detection already returns,
-- findFirstByFileHashOrderByUploadedAtDesc) and clear it on the older copies. file_hash is used
-- only for duplicate detection and is shown nowhere, so nothing visible changes. Postgres allows
-- any number of NULLs under a unique index.
UPDATE files f
SET file_hash = NULL
FROM (
  SELECT id,
         row_number() OVER (PARTITION BY file_hash ORDER BY uploaded_at DESC, id DESC) AS rn
  FROM files
  WHERE file_hash IS NOT NULL
) ranked
WHERE f.id = ranked.id
  AND ranked.rn > 1;

DROP INDEX IF EXISTS idx_files_file_hash;
CREATE UNIQUE INDEX uq_files_file_hash ON files (file_hash);
