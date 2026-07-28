-- ── Partition `packets` by file_id for O(1) retention cleanup (#394) ──
-- `packets` is the dominant table (~1.5-2M rows per GB of PCAP; the DB grows ~1-1.5x PCAP size,
-- almost entirely packets). Retention deletes whole files, and ON DELETE CASCADE then removed
-- millions of rows per file every cleanup cycle — a burst of dead tuples, index churn and
-- autovacuum work competing with live analysis.
--
-- Deletion is per-file, so LIST partitioning on file_id makes the partition boundary match the
-- deletion boundary exactly: retention becomes `DROP TABLE packets_<fileid>`, an O(1) unlink with
-- no row visits, no index maintenance and nothing left for autovacuum. Per-file queries also prune
-- to a single small partition instead of scanning an index spanning every file.
--
-- (Time-range partitioning / TimescaleDB would not help: nothing here is deleted by time window.)
--
-- Notes on the shape below:
--   * Postgres requires the partition key in every unique constraint, so the primary key widens
--     from (id) to (id, file_id). `id` stays globally unique in practice — it is a UUID — and JPA
--     continues to treat it as the sole @Id.
--   * The FK to conversations is declared per-partition rather than on the parent: a partitioned
--     table cannot be the target of a FK, but it can be the source. Declaring it on the parent
--     would still work, but keeping it with the partition means DROP TABLE takes the constraint
--     with it and never leaves a dangling trigger.
--   * There is deliberately NO default partition. A missing partition must fail loudly at insert
--     rather than silently landing rows somewhere that cannot be dropped instantly, and attaching
--     a new partition would have to scan the default under an ACCESS EXCLUSIVE lock.

ALTER TABLE packets RENAME TO packets_unpartitioned;

-- Old indexes would collide by name with the ones recreated on the partitioned table below.
ALTER INDEX idx_packet_file_id   RENAME TO idx_packet_file_id_old;
ALTER INDEX idx_packet_conv_id   RENAME TO idx_packet_conv_id_old;
ALTER INDEX idx_packet_timestamp RENAME TO idx_packet_timestamp_old;
ALTER INDEX idx_packet_number    RENAME TO idx_packet_number_old;

CREATE TABLE packets (
    id                  UUID        NOT NULL,
    file_id             UUID        NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    conversation_id     UUID,
    packet_number       BIGINT      NOT NULL,
    timestamp           TIMESTAMP   NOT NULL,
    src_ip              VARCHAR(45) NOT NULL,
    src_port            INTEGER,
    dst_ip              VARCHAR(45) NOT NULL,
    dst_port            INTEGER,
    protocol            VARCHAR(100) NOT NULL,
    packet_size         INTEGER     NOT NULL,
    payload             TEXT,
    detected_file_type  VARCHAR(32),
    info                TEXT,
    created_at          TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id, file_id)
) PARTITION BY LIST (file_id);

-- Declared on the parent; Postgres creates a matching index on every partition, existing and future.
CREATE INDEX idx_packet_file_id   ON packets (file_id);
CREATE INDEX idx_packet_conv_id   ON packets (conversation_id);
CREATE INDEX idx_packet_timestamp ON packets (timestamp);
CREATE INDEX idx_packet_number    ON packets (file_id, packet_number);

-- ── Carry existing rows across ────────────────────────────────────────────────
-- One partition per file_id that currently has packets, then a single INSERT..SELECT. Packets are
-- short-lived (12h default retention) so this is normally a small or empty set; on a fresh install
-- both loops are no-ops.
DO $$
DECLARE
    fid        UUID;
    part_name  TEXT;
BEGIN
    FOR fid IN SELECT DISTINCT file_id FROM packets_unpartitioned LOOP
        part_name := 'packets_' || replace(fid::text, '-', '');
        EXECUTE format(
            'CREATE TABLE %I PARTITION OF packets FOR VALUES IN (%L)', part_name, fid);
        EXECUTE format(
            'ALTER TABLE %I ADD FOREIGN KEY (conversation_id) '
            || 'REFERENCES conversations (id) ON DELETE CASCADE', part_name);
    END LOOP;
END $$;

INSERT INTO packets (
    id, file_id, conversation_id, packet_number, timestamp, src_ip, src_port,
    dst_ip, dst_port, protocol, packet_size, payload, detected_file_type, info, created_at)
SELECT
    id, file_id, conversation_id, packet_number, timestamp, src_ip, src_port,
    dst_ip, dst_port, protocol, packet_size, payload, detected_file_type, info, created_at
FROM packets_unpartitioned;

DROP TABLE packets_unpartitioned;

-- ── Decouple packet retention from summary retention ──────────────────────────
-- Packets are the bulky part; conversations / analysis_results are compact summaries that stay
-- useful long after the raw frames are worth storing. This column lets cleanup prune packet
-- partitions on a shorter clock than the file itself, and lets the UI tell "no packets in this
-- capture" apart from "packet detail has been pruned". NULL = packets still present.
ALTER TABLE files
    ADD COLUMN packets_pruned_at TIMESTAMP;

-- Retention sweep looks up not-yet-pruned files by age.
CREATE INDEX idx_files_packets_pruned_at ON files (packets_pruned_at, uploaded_at);
