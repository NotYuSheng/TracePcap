-- A capture's own deletion time, when someone extended it past the retention window. Null means
-- the retention window applies (and keep_forever still wins over both).
ALTER TABLE files ADD COLUMN expires_at TIMESTAMP(3);

-- Captures an account marked as favourites, to find them again. Personal: keyed by the same
-- profile as the preferences (the account when login is on, one shared profile when it's off).
CREATE TABLE file_favourites (
    profile_key VARCHAR(255) NOT NULL,
    file_id     UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    created_at  TIMESTAMP(3) NOT NULL DEFAULT now(),
    PRIMARY KEY (profile_key, file_id)
);
