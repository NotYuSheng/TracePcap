CREATE TABLE host_classifications (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id     UUID NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    ip          VARCHAR(45) NOT NULL,
    mac         VARCHAR(17),
    manufacturer VARCHAR(100),
    ttl         INTEGER,
    device_type VARCHAR(50) NOT NULL,
    confidence  INTEGER NOT NULL,
    UNIQUE (file_id, ip)
);

CREATE INDEX idx_host_class_file_id ON host_classifications(file_id);
