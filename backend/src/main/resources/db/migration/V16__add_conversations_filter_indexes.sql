-- Indexes to support the new structured filter and sort params on /api/conversations
CREATE INDEX IF NOT EXISTS idx_conv_app_name      ON conversations(file_id, app_name);
CREATE INDEX IF NOT EXISTS idx_conv_category      ON conversations(file_id, category);
CREATE INDEX IF NOT EXISTS idx_conv_start_time    ON conversations(file_id, start_time);
CREATE INDEX IF NOT EXISTS idx_conv_packet_count  ON conversations(file_id, packet_count);
CREATE INDEX IF NOT EXISTS idx_conv_total_bytes   ON conversations(file_id, total_bytes);
