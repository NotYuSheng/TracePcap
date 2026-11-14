-- #918 slice 3: labels moved off a device when its boundary went away (a merge, or undoing a
-- split), so they go back to it when the device reappears (undoing the merge). One row per label.
--   kind      override | evidence | role
--   question  the override's or evidence's question; null for a role
CREATE TABLE device_label_moves (
    id         BIGSERIAL    PRIMARY KEY,
    file_id    UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    kind       VARCHAR(10)  NOT NULL,
    question   VARCHAR(64),
    row_id     BIGINT       NOT NULL,
    from_key   VARCHAR(255) NOT NULL,
    to_key     VARCHAR(255) NOT NULL,
    moved_at   TIMESTAMP    NOT NULL DEFAULT now()
);
CREATE INDEX device_label_moves_file ON device_label_moves (file_id);
