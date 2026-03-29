ALTER TABLE conversations ADD COLUMN IF NOT EXISTS custom_signatures text[];
CREATE INDEX IF NOT EXISTS idx_conversations_custom_signatures ON conversations USING GIN (custom_signatures);
