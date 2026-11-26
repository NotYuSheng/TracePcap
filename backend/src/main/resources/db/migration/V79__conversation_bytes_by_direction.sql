-- Bytes each side sent, so a large download isn't mistaken for an upload (the bulk-transfer answer
-- said "sent 6 MB" for a 6 MB file the host received). NULL for captures analysed before this.
ALTER TABLE conversations ADD COLUMN bytes_src_to_dst BIGINT;
ALTER TABLE conversations ADD COLUMN bytes_dst_to_src BIGINT;
