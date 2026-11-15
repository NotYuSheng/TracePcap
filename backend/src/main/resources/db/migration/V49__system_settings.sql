-- Editable analysis policy (#915 phase 5). An override of a deploy-time setting, keyed by its
-- environment variable name. No row means the env value (or its default) is in effect, so deleting
-- a row resets the setting. Which keys may be stored is decided by the code (EditablePolicy), not
-- here. Every change is audited.
CREATE TABLE system_settings (
    key         VARCHAR(100) PRIMARY KEY,
    value       VARCHAR(255) NOT NULL,
    updated_at  TIMESTAMP    NOT NULL DEFAULT now(),
    updated_by  VARCHAR(255) NOT NULL
);
