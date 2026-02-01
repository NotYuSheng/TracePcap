-- Create stories table for AI-generated network traffic narratives
CREATE TABLE stories (
    id UUID PRIMARY KEY,
    file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    generated_at TIMESTAMP NOT NULL,
    content TEXT NOT NULL,
    model_used VARCHAR(100),
    tokens_used INTEGER,
    status VARCHAR(50) NOT NULL,
    error_message TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_story_file FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
);

-- Create index on file_id for faster lookups
CREATE INDEX idx_stories_file_id ON stories(file_id);

-- Create index on generated_at for sorting
CREATE INDEX idx_stories_generated_at ON stories(generated_at DESC);

-- Create index on status for filtering
CREATE INDEX idx_stories_status ON stories(status);
