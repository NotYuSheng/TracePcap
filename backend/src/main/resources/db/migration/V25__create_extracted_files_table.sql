CREATE TABLE extracted_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    conversation_id UUID REFERENCES conversations(id) ON DELETE SET NULL,
    filename VARCHAR(500),
    mime_type VARCHAR(200),
    file_size BIGINT,
    sha256 VARCHAR(64),
    minio_path VARCHAR(1000) NOT NULL,
    extraction_method VARCHAR(50),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_extracted_file_id ON extracted_files(file_id);
CREATE INDEX idx_extracted_conv_id ON extracted_files(conversation_id);
