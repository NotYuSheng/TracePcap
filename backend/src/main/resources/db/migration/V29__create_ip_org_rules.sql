CREATE TABLE ip_org_rules (
    id           BIGSERIAL PRIMARY KEY,
    label        VARCHAR(255) NOT NULL,
    cidr         VARCHAR(50)  NOT NULL,
    prefix_length INT         NOT NULL,
    created_at   TIMESTAMP    NOT NULL DEFAULT NOW()
);
