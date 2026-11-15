-- Re-analysis as a new version (#915 phase 3). Re-analysing a capture with different options
-- creates a new file row (and its own copy of the capture in storage), leaving the original and
-- its analysis as they were.
--   derived_from: the original capture; null for an upload. If the original is deleted, its
--     versions stay, as versions.
--   is_version: a re-analysis rather than an upload. The duplicate-upload check (#885, V44) only
--     applies to uploads, so versions share their original's hash.
ALTER TABLE files
    ADD COLUMN derived_from UUID REFERENCES files (id) ON DELETE SET NULL,
    ADD COLUMN is_version BOOLEAN NOT NULL DEFAULT FALSE;
DROP INDEX IF EXISTS uq_files_file_hash;
CREATE UNIQUE INDEX uq_files_file_hash ON files (file_hash) WHERE NOT is_version;
CREATE INDEX idx_files_derived_from ON files (derived_from) WHERE derived_from IS NOT NULL;
