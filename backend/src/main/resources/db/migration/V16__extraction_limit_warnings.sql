-- Record details of when configurable file-extraction limits were hit so the UI can warn that
-- extraction results may be incomplete and point users at the specific streams/files (see #324).
--
-- The per-file size limit needs no column here: skipped files are already persisted in
-- extracted_files with skipped_reason = 'exceeds_size_limit', and are listed from there.
ALTER TABLE files
    ADD COLUMN extraction_match_limit_conv_ids             TEXT,
    ADD COLUMN extraction_conversation_limit_skipped_count INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN extraction_conversation_limit_skipped_ids   TEXT;
