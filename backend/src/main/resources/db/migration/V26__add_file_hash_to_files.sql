ALTER TABLE files ADD COLUMN IF NOT EXISTS file_hash VARCHAR(64);

CREATE INDEX IF NOT EXISTS idx_files_file_hash ON files (file_hash);
