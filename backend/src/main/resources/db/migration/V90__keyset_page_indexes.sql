-- A file's conversations and hosts are read a page at a time in id order (common/db/InPages, #1373):
-- WHERE file_id = ? AND id > ? ORDER BY id LIMIT n. With only (file_id), Postgres walked the primary
-- key across every file's rows: one page took 44 s on a 1.2M-row table.
CREATE INDEX idx_conv_file_id_id ON conversations (file_id, id);
-- (file_id, id) answers everything (file_id) did.
DROP INDEX IF EXISTS idx_conv_file_id;

CREATE INDEX idx_host_class_file_id_id ON host_classifications (file_id, id);
