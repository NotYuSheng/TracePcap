ALTER TABLE snapshot_subnet_overrides
    ADD CONSTRAINT uq_snapshot_subnet_overrides_snapshot_cidr UNIQUE (snapshot_id, cidr);
