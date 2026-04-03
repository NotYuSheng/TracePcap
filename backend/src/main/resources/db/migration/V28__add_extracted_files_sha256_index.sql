-- Composite index to speed up the duplicate-detection query (existsByFileIdAndSha256)
-- called for every candidate file during raw-stream extraction.
CREATE INDEX idx_extracted_files_file_id_sha256
    ON extracted_files (file_id, sha256);
