package com.tracepcap.analysis.service;

import com.tracepcap.analysis.spi.PacketPartitions;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Serves {@link PacketPartitions} with DDL against the partitioned {@code packets} table (#394).
 *
 * <p>Raw JDBC rather than JPA: these are {@code CREATE TABLE} / {@code DROP TABLE} statements, which
 * have no entity to map and must not be caught up in Hibernate's flush ordering — the partition has
 * to be committed and visible before any packet insert for the file is attempted.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class PacketPartitionAdapter implements PacketPartitions {

  private final JdbcTemplate jdbc;

  /**
   * Partition name for a file: {@code packets_} + the UUID with dashes stripped.
   *
   * <p>Dashes are removed because they would need quoting in an identifier; the result is 39
   * characters, inside Postgres' 63-byte {@code NAMEDATALEN} limit. The value is a parsed {@link
   * UUID} rather than caller-supplied text, so it cannot carry anything but hex and is safe to
   * interpolate — identifiers cannot be bound as JDBC parameters.
   */
  private static String partitionName(UUID fileId) {
    return "packets_" + fileId.toString().replace("-", "");
  }

  @Override
  public void ensurePartition(UUID fileId) {
    String name = partitionName(fileId);

    // IF NOT EXISTS keeps this idempotent for retries and restarts mid-analysis.
    jdbc.execute(
        "CREATE TABLE IF NOT EXISTS "
            + name
            + " PARTITION OF packets FOR VALUES IN ('"
            + fileId
            + "')");

    // The FK to conversations lives on the partition, not the parent, so DROP TABLE takes the
    // constraint with it. Adding it separately means it must be guarded: unlike CREATE TABLE,
    // ADD CONSTRAINT has no IF NOT EXISTS, and this method is called more than once per file.
    Integer existing =
        jdbc.queryForObject(
            "SELECT count(*) FROM pg_constraint WHERE conrelid = ?::regclass AND contype = 'f'",
            Integer.class,
            name);
    if (existing != null && existing == 0) {
      jdbc.execute(
          "ALTER TABLE "
              + name
              + " ADD FOREIGN KEY (conversation_id) REFERENCES conversations (id) ON DELETE CASCADE");
    }

    log.debug("Ensured packet partition {} for file {}", name, fileId);
  }

  @Override
  public boolean dropPartition(UUID fileId) {
    String name = partitionName(fileId);

    // to_regclass returns NULL rather than throwing when the table is absent, so an already-pruned
    // file is reported as "nothing dropped" instead of an error.
    String resolved =
        jdbc.queryForObject("SELECT to_regclass(?)::text", String.class, "public." + name);
    if (resolved == null) {
      return false;
    }

    jdbc.execute("DROP TABLE " + name);
    log.info("Dropped packet partition {} for file {}", name, fileId);
    return true;
  }
}
