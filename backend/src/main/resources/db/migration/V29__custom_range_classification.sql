-- Allow custom IP/CIDR overrides to force either classification, not just private.
-- Existing rows were all "treat as private", so default preserves current behaviour.
ALTER TABLE custom_private_ranges
    ADD COLUMN classification VARCHAR(16) NOT NULL DEFAULT 'PRIVATE';

ALTER TABLE custom_private_ranges
    ADD CONSTRAINT custom_private_ranges_classification_chk
        CHECK (classification IN ('PRIVATE', 'PUBLIC'));
