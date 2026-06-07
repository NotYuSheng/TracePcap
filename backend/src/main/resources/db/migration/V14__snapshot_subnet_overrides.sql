CREATE TABLE snapshot_subnet_overrides (
    id          BIGSERIAL    PRIMARY KEY,
    snapshot_id UUID         NOT NULL REFERENCES network_snapshots(id) ON DELETE CASCADE,
    cidr        VARCHAR(50)  NOT NULL,
    label       VARCHAR(255),
    description TEXT,
    inherited   BOOLEAN      NOT NULL DEFAULT false
);

CREATE INDEX idx_snapshot_subnet_overrides_snapshot_id ON snapshot_subnet_overrides(snapshot_id);
