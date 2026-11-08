-- Audit log (#915): who changed what, when, with the value before and after. Append-only.
-- actor is the login's username, or 'system' when login is off.
CREATE TABLE audit_log (
    id           BIGSERIAL    PRIMARY KEY,
    at           TIMESTAMP    NOT NULL DEFAULT now(),
    actor        VARCHAR(255) NOT NULL,
    action       VARCHAR(100) NOT NULL,
    target_type  VARCHAR(100) NOT NULL,
    target_id    VARCHAR(255),
    before_value JSONB,
    after_value  JSONB
);
CREATE INDEX idx_audit_log_at ON audit_log (at DESC);
CREATE INDEX idx_audit_log_target ON audit_log (target_type, target_id);

-- Who may perform each configurable action (#915): ANALYST (anyone signed in) or ADMIN (the
-- Keycloak client role admin). Only overrides are stored; an action without a row uses its
-- built-in default. Changing these is always admin-only and is audited.
CREATE TABLE permissions (
    action      VARCHAR(100) PRIMARY KEY,
    level       VARCHAR(20)  NOT NULL CHECK (level IN ('ANALYST', 'ADMIN')),
    updated_at  TIMESTAMP    NOT NULL DEFAULT now(),
    updated_by  VARCHAR(255) NOT NULL
);
