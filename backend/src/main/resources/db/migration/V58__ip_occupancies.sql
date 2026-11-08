-- #918 item 3, slice 1: time-bounded host occupancy. An "occupancy" is one device holding one
-- address for a stretch of the capture. A host is still (file_id, ip); this slice records and
-- shows occupancies without changing any key.

-- When each ARP ownership claim was first and last seen, so a sequence (aa until 10:59, then bb)
-- can be told apart from two devices answering at once. Null on rows from before this migration.
ALTER TABLE ip_mac_observations
    ADD COLUMN first_seen TIMESTAMP(3),
    ADD COLUMN last_seen  TIMESTAMP(3);

-- DHCP leases: an ACK (or a REQUEST) for an address to a client MAC, with the hostname the client
-- asked under. One row per (file, ip, client MAC) with its first and last time.
CREATE TABLE dhcp_leases (
    id         BIGSERIAL    PRIMARY KEY,
    file_id    UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    ip         VARCHAR(45)  NOT NULL,
    mac        VARCHAR(50)  NOT NULL,
    hostname   VARCHAR(255),
    first_seen TIMESTAMP(3) NOT NULL,
    last_seen  TIMESTAMP(3) NOT NULL,
    UNIQUE (file_id, ip, mac)
);

-- Analyst decisions on where one device ends and the next begins. Kept apart from the derived
-- occupancies so recomputing (or re-analysing, #951) never loses them.
--   split: a boundary at `at`, even with no MAC change
--   merge: removes the automatic boundary at `at` ("not a different device")
CREATE TABLE occupancy_decisions (
    id         BIGSERIAL    PRIMARY KEY,
    file_id    UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    ip         VARCHAR(45)  NOT NULL,
    at         TIMESTAMP(3) NOT NULL,
    action     VARCHAR(10)  NOT NULL CHECK (action IN ('split', 'merge')),
    reason     TEXT         NOT NULL,
    actor      VARCHAR(255),
    created_at TIMESTAMP    NOT NULL DEFAULT now(),
    UNIQUE (file_id, ip, at, action)
);

-- Derived: rows exist only for addresses with more than one occupancy (no rows = one device for
-- the whole capture). starts_at is null for the first occupancy and ends_at null for the last;
-- an occupancy covers [starts_at, ends_at).
-- segment_key is reserved for #462 (overlapping ranges at two sites); unused until then.
CREATE TABLE ip_occupancies (
    id             BIGSERIAL    PRIMARY KEY,
    file_id        UUID         NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    ip             VARCHAR(45)  NOT NULL,
    segment_key    VARCHAR(64),
    idx            INT          NOT NULL,
    mac            VARCHAR(50),
    hostname       VARCHAR(255),
    starts_at      TIMESTAMP(3),
    ends_at        TIMESTAMP(3),
    start_source   VARCHAR(10),
    start_evidence TEXT,
    UNIQUE (file_id, ip, idx)
);
