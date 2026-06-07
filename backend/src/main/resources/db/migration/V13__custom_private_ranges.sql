CREATE TABLE custom_private_ranges (
    id         BIGSERIAL    PRIMARY KEY,
    cidr       VARCHAR(50)  NOT NULL UNIQUE,
    label      VARCHAR(255),
    created_at TIMESTAMP    NOT NULL DEFAULT NOW()
);
