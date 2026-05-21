CREATE TABLE subnet_definitions (
    id          BIGSERIAL    PRIMARY KEY,
    cidr        VARCHAR(50)  NOT NULL UNIQUE,
    label       VARCHAR(100),
    description TEXT,
    source      VARCHAR(10)  NOT NULL DEFAULT 'MANUAL',
    confirmed   BOOLEAN      NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TRIGGER update_subnet_definitions_updated_at
    BEFORE UPDATE ON subnet_definitions
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
