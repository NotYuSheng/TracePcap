-- Allow extracted_files rows to represent files that were detected but not stored
-- (e.g. exceeded the 50 MB per-file size limit). minio_path becomes nullable so
-- these sentinel rows don't need a placeholder value.
ALTER TABLE extracted_files
    ALTER COLUMN minio_path DROP NOT NULL,
    ADD COLUMN skipped_reason VARCHAR(100);
