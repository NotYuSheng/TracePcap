-- #915 phase 4: per-network address configuration. Subnet labels, private/public range
-- overrides and IP-org rules become a shared default (network_id IS NULL) plus per-network
-- entries layered on top, per CIDR:
--   override  a network row for a CIDR the default also has replaces it in that network
--   add       a network row for a CIDR the default doesn't have
--   hide      a network row with hidden = true removes the default's CIDR in that network
-- Existing rows become the default; nothing is copied into networks.

ALTER TABLE custom_private_ranges
    ADD COLUMN network_id UUID REFERENCES networks (id) ON DELETE CASCADE,
    ADD COLUMN hidden     BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT custom_private_ranges_default_not_hidden CHECK (network_id IS NOT NULL OR NOT hidden);
ALTER TABLE custom_private_ranges DROP CONSTRAINT custom_private_ranges_cidr_key;
CREATE UNIQUE INDEX custom_private_ranges_default_cidr ON custom_private_ranges (cidr) WHERE network_id IS NULL;
CREATE UNIQUE INDEX custom_private_ranges_network_cidr ON custom_private_ranges (network_id, cidr) WHERE network_id IS NOT NULL;

ALTER TABLE subnet_definitions
    ADD COLUMN network_id UUID REFERENCES networks (id) ON DELETE CASCADE,
    ADD COLUMN hidden     BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT subnet_definitions_default_not_hidden CHECK (network_id IS NOT NULL OR NOT hidden);
ALTER TABLE subnet_definitions DROP CONSTRAINT subnet_definitions_cidr_key;
CREATE UNIQUE INDEX subnet_definitions_default_cidr ON subnet_definitions (cidr) WHERE network_id IS NULL;
CREATE UNIQUE INDEX subnet_definitions_network_cidr ON subnet_definitions (network_id, cidr) WHERE network_id IS NOT NULL;

-- ip_org_rules never had a unique CIDR (an install may have duplicates), so only network rows get one.
ALTER TABLE ip_org_rules
    ADD COLUMN network_id UUID REFERENCES networks (id) ON DELETE CASCADE,
    ADD COLUMN hidden     BOOLEAN NOT NULL DEFAULT FALSE,
    ADD CONSTRAINT ip_org_rules_default_not_hidden CHECK (network_id IS NOT NULL OR NOT hidden);
CREATE UNIQUE INDEX ip_org_rules_network_cidr ON ip_org_rules (network_id, cidr) WHERE network_id IS NOT NULL;

-- Subnet staleness baselines move to per network (#363). "This subnet's composition changed" only
-- means something against one network's snapshots; a single shared baseline meant dismissing
-- staleness in one network re-baselined it for all of them.
CREATE TABLE subnet_network_baselines (
    subnet_id            BIGINT    NOT NULL REFERENCES subnet_definitions (id) ON DELETE CASCADE,
    network_id           UUID      NOT NULL REFERENCES networks (id) ON DELETE CASCADE,
    labeled_at           TIMESTAMP,
    baseline_file_id     UUID,
    baseline_composition JSONB,
    stale_since          TIMESTAMP,
    stale_fields         JSONB,
    PRIMARY KEY (subnet_id, network_id)
);

-- Carry each existing baseline to the network(s) whose snapshot it was computed from.
INSERT INTO subnet_network_baselines
    (subnet_id, network_id, labeled_at, baseline_file_id, baseline_composition, stale_since, stale_fields)
SELECT DISTINCT ON (s.id, ns.network_id)
       s.id, ns.network_id, s.labeled_at, s.baseline_file_id, s.baseline_composition, s.stale_since, s.stale_fields
FROM subnet_definitions s
JOIN network_snapshots ns ON ns.file_id = s.baseline_file_id
WHERE s.baseline_file_id IS NOT NULL;

ALTER TABLE subnet_definitions
    DROP COLUMN labeled_at,
    DROP COLUMN baseline_file_id,
    DROP COLUMN baseline_composition,
    DROP COLUMN stale_since,
    DROP COLUMN stale_fields;
