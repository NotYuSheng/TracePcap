-- Detection rules in the database (#925 phase 1). Replaces the mounted signatures.yml; the
-- existing file is imported once by V51. The database is the only source of truth; YAML stays as
-- an export/import format, not configuration.
--
-- scope: GLOBAL applies to every capture. NETWORK and CAPTURE (#925 phase 3) belong to a network
-- or a single capture and are not evaluated yet.
-- match / payload_contains / payload_regex keep the YAML rule shape, so the matching engine and
-- export/import are unchanged.
-- device_type is legacy: it still overrides classification as before, but can no longer be set
-- in the editor. #926 moves it to a weighted classification signal.
CREATE TABLE detection_rules (
    id                UUID         PRIMARY KEY,
    scope             VARCHAR(20)  NOT NULL DEFAULT 'GLOBAL' CHECK (scope IN ('GLOBAL', 'NETWORK', 'CAPTURE')),
    network_id        UUID         REFERENCES networks(id) ON DELETE CASCADE,
    file_id           UUID         REFERENCES files(id) ON DELETE CASCADE,
    name              VARCHAR(200) NOT NULL,
    description       TEXT,
    severity          VARCHAR(20)  NOT NULL DEFAULT 'low' CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    enabled           BOOLEAN      NOT NULL DEFAULT TRUE,
    match_criteria    JSONB        NOT NULL DEFAULT '{}'::jsonb,
    payload_contains  JSONB        NOT NULL DEFAULT '[]'::jsonb,
    payload_regex     JSONB        NOT NULL DEFAULT '[]'::jsonb,
    match_all         BOOLEAN      NOT NULL DEFAULT FALSE,
    device_type       VARCHAR(100),
    version           INTEGER      NOT NULL DEFAULT 1,
    created_at        TIMESTAMP    NOT NULL DEFAULT now(),
    created_by        VARCHAR(255) NOT NULL,
    updated_at        TIMESTAMP    NOT NULL DEFAULT now(),
    updated_by        VARCHAR(255) NOT NULL,
    CHECK ((scope = 'GLOBAL'  AND network_id IS NULL AND file_id IS NULL)
        OR (scope = 'NETWORK' AND network_id IS NOT NULL AND file_id IS NULL)
        OR (scope = 'CAPTURE' AND file_id IS NOT NULL AND network_id IS NULL))
);

-- A rule's name is what a match is labelled with, so it's unique within its scope.
CREATE UNIQUE INDEX uq_detection_rules_global_name ON detection_rules (lower(name)) WHERE scope = 'GLOBAL';
CREATE UNIQUE INDEX uq_detection_rules_network_name ON detection_rules (network_id, lower(name)) WHERE scope = 'NETWORK';
CREATE UNIQUE INDEX uq_detection_rules_capture_name ON detection_rules (file_id, lower(name)) WHERE scope = 'CAPTURE';
