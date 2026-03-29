ALTER TABLE conversations ADD COLUMN IF NOT EXISTS http_user_agents TEXT[];
CREATE INDEX IF NOT EXISTS idx_conversations_http_user_agents ON conversations USING GIN (http_user_agents);
