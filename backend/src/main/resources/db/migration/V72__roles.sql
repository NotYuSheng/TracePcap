-- Roles (replaces V48's per-action levels). A role is a set of permissions. Who has a role is
-- decided in Keycloak: the role's key is a client role on the app's client (tracepcap-frontend),
-- assigned there to groups or people. TracePcap decides only what each role may do.
--
-- Four built-in roles: viewer, analyst, lead and admin. admin always has every permission (the
-- break-glass role) and isn't stored here as a list. Someone whose sign-in carries none of the
-- roles gets the default one: analyst, so an upgrade changes nothing for people who had no role.
CREATE TABLE roles (
    role_key     VARCHAR(100) PRIMARY KEY,
    label        VARCHAR(200) NOT NULL,
    description  TEXT,
    built_in     BOOLEAN      NOT NULL DEFAULT FALSE,
    position     INT          NOT NULL DEFAULT 100,
    is_default   BOOLEAN      NOT NULL DEFAULT FALSE,
    updated_at   TIMESTAMP    NOT NULL DEFAULT now(),
    updated_by   VARCHAR(255) NOT NULL DEFAULT 'system'
);
-- At most one default role.
CREATE UNIQUE INDEX roles_one_default ON roles (is_default) WHERE is_default;

CREATE TABLE role_permissions (
    role_key  VARCHAR(100) NOT NULL REFERENCES roles (role_key) ON DELETE CASCADE,
    action    VARCHAR(100) NOT NULL,
    PRIMARY KEY (role_key, action)
);

INSERT INTO roles (role_key, label, description, built_in, position, is_default) VALUES
 ('viewer',  'Viewer',  'Looks: reads captures, networks, findings and reports. Changes nothing.', TRUE, 10, FALSE),
 ('analyst', 'Analyst', 'Investigates: uploads, asks the AI, labels, overrides, writes capture and network rules, deletes their own captures.', TRUE, 20, TRUE),
 ('lead',    'Lead',    'Curates what everyone shares: global rules, address defaults, network settings, anyone''s captures, the audit log.', TRUE, 30, FALSE),
 ('admin',   'Admin',   'Runs the install: retention, analysis policy, the LLM connection, and roles. Always has every permission.', TRUE, 40, FALSE);

-- Each permission's lowest built-in role (1 viewer, 2 analyst, 3 lead, 4 admin); a role gets the
-- permissions whose lowest role is at or below it. The ten that existed before (V48) keep the level
-- this install had set: ANALYST becomes analyst, ADMIN becomes admin only.
CREATE TEMPORARY TABLE seed_permissions (action VARCHAR(100), lowest INT);
INSERT INTO seed_permissions (action, lowest) VALUES
 ('SEE_CAPTURES', 1), ('DOWNLOAD_REPORT', 1), ('READ_AUDIT_LOG', 3),
 ('UPLOAD_CAPTURES', 2), ('ASK_AI', 2), ('EXPORT_PACKETS', 2),
 ('LABEL_HOSTS', 2), ('OVERRIDE_ANSWERS', 2),
 ('NETWORK_CAPTURES', 2), ('NETWORK_CREATE', 2), ('NETWORK_DELETE', 3),
 ('KEEP_CAPTURES', 2), ('DELETE_OWN_CAPTURES', 2), ('DELETE_ANY_CAPTURES', 3),
 ('CANCEL_OTHERS_AI_JOBS', 3);
INSERT INTO seed_permissions (action, lowest)
SELECT d.action, CASE COALESCE(p.level, d.level) WHEN 'ADMIN' THEN 4 ELSE 2 END
FROM (VALUES
  ('DETECTION_RULES_GLOBAL', 'ANALYST'), ('DETECTION_RULES_NETWORK', 'ANALYST'),
  ('DETECTION_RULES_CAPTURE', 'ANALYST'), ('HOST_OCCUPANCY', 'ANALYST'),
  ('ADDRESS_DEFAULTS', 'ANALYST'), ('NETWORK_SETTINGS', 'ANALYST'), ('NETWORK_MAP', 'ANALYST'),
  ('ANALYSIS_POLICY', 'ANALYST'), ('RETENTION', 'ADMIN'), ('LLM_CONNECTION', 'ADMIN')
) AS d (action, level)
LEFT JOIN permissions p ON p.action = d.action;

INSERT INTO role_permissions (role_key, action)
SELECT r.role_key, s.action
FROM seed_permissions s
JOIN (VALUES ('viewer', 1), ('analyst', 2), ('lead', 3)) AS r (role_key, rank) ON r.rank >= s.lowest;

DROP TABLE seed_permissions;
DROP TABLE permissions;

-- Who uploaded a capture, for "delete your own captures". The login's username, or 'system' with
-- login off. Captures uploaded before this have none, so only a role that may delete anyone's can.
ALTER TABLE files ADD COLUMN uploaded_by VARCHAR(255);
