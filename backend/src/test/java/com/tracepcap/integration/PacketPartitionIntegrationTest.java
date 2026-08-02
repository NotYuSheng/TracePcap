package com.tracepcap.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.PacketPartitions;
import java.time.LocalDateTime;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Verifies the packet partitioning introduced in #394, against a real Flyway-migrated Postgres.
 *
 * <p>The properties under test are structural rather than behavioural — that {@code packets} is
 * partitioned at all, that a partition is created per file and dropped whole, and that dropping one
 * leaves both other files' packets and this file's summaries alone. None of that is observable
 * through the API, so these assert against the catalog directly.
 */
@SpringBootTest
@Testcontainers
class PacketPartitionIntegrationTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(DockerImageName.parse("postgres:15-alpine"));

  @Container
  static final GenericContainer<?> MINIO =
      new GenericContainer<>(DockerImageName.parse("minio/minio:RELEASE.2024-01-28T22-35-53Z"))
          .withEnv("MINIO_ROOT_USER", "minioadmin")
          .withEnv("MINIO_ROOT_PASSWORD", "minioadmin")
          .withCommand("server", "/data")
          .withExposedPorts(9000)
          .waitingFor(Wait.forHttp("/minio/health/ready").forPort(9000));

  @DynamicPropertySource
  static void properties(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
    registry.add("spring.datasource.username", POSTGRES::getUsername);
    registry.add("spring.datasource.password", POSTGRES::getPassword);
    registry.add(
        "minio.endpoint", () -> "http://" + MINIO.getHost() + ":" + MINIO.getMappedPort(9000));
    registry.add("minio.access-key", () -> "minioadmin");
    registry.add("minio.secret-key", () -> "minioadmin");
  }

  @Autowired private PacketPartitions packetPartitions;
  @Autowired private JdbcTemplate jdbc;

  @Test
  void packetsTable_isPartitionedByFileId() {
    // 'p' = partitioned table; partstrat 'l' = LIST. Without both, retention silently falls back to
    // a cascading delete and the whole change is a no-op.
    String kind =
        jdbc.queryForObject(
            "SELECT relkind::text FROM pg_class WHERE relname = 'packets'", String.class);
    String strategy =
        jdbc.queryForObject(
            "SELECT partstrat::text FROM pg_partitioned_table WHERE partrelid = 'packets'::regclass",
            String.class);

    assertThat(kind).isEqualTo("p");
    assertThat(strategy).isEqualTo("l");
  }

  @Test
  void primaryKey_includesPartitionKey() {
    // Postgres rejects a unique constraint that omits the partition key, so the PK had to widen to
    // (id, file_id). Asserted because it is the one schema change JPA does not validate.
    Integer pkColumns =
        jdbc.queryForObject(
            "SELECT cardinality(conkey) FROM pg_constraint"
                + " WHERE conrelid = 'packets'::regclass AND contype = 'p'",
            Integer.class);

    assertThat(pkColumns).isEqualTo(2);
  }

  @Test
  void ensurePartition_isIdempotent() {
    UUID fileId = insertFile();

    packetPartitions.ensurePartition(fileId);
    // Called again the way a retried or resumed analysis would.
    packetPartitions.ensurePartition(fileId);

    assertThat(partitionCount(fileId)).isEqualTo(1);
    // The FK to conversations lives on the partition; the second call must not duplicate it.
    assertThat(foreignKeyCount(fileId)).isEqualTo(1);
  }

  @Test
  void dropPartition_removesOnlyThatFilesPackets() {
    UUID kept = insertFile();
    UUID dropped = insertFile();
    packetPartitions.ensurePartition(kept);
    packetPartitions.ensurePartition(dropped);
    insertPacket(kept, 1L);
    insertPacket(dropped, 1L);
    insertPacket(dropped, 2L);

    boolean didDrop = packetPartitions.dropPartition(dropped);

    assertThat(didDrop).isTrue();
    assertThat(packetCount(dropped)).isZero();
    assertThat(packetCount(kept)).isEqualTo(1);
    // The file itself outlives its packets — that is what makes packet retention separable.
    assertThat(fileExists(dropped)).isTrue();
  }

  @Test
  void dropPartition_onAlreadyPrunedFile_isNoOp() {
    UUID fileId = insertFile();
    packetPartitions.ensurePartition(fileId);
    packetPartitions.dropPartition(fileId);

    // Retention and file deletion can both reach the same file; the second must not throw.
    assertThat(packetPartitions.dropPartition(fileId)).isFalse();
  }

  @Test
  void dropPartition_onFileThatNeverHadOne_isNoOp() {
    assertThat(packetPartitions.dropPartition(UUID.randomUUID())).isFalse();
  }

  private UUID insertFile() {
    UUID id = UUID.randomUUID();
    jdbc.update(
        "INSERT INTO files (id, file_name, file_size, minio_path, uploaded_at, status)"
            + " VALUES (?, ?, ?, ?, ?, ?)",
        id,
        id + ".pcap",
        1024L,
        "s3://test/" + id,
        LocalDateTime.now(),
        "COMPLETED");
    return id;
  }

  private void insertPacket(UUID fileId, long packetNumber) {
    jdbc.update(
        "INSERT INTO packets (id, file_id, packet_number, timestamp, src_ip, dst_ip, protocol,"
            + " packet_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        UUID.randomUUID(),
        fileId,
        packetNumber,
        LocalDateTime.now(),
        "192.168.1.10",
        "192.168.1.11",
        "ARP",
        42);
  }

  private String partitionName(UUID fileId) {
    return "packets_" + fileId.toString().replace("-", "");
  }

  private Integer partitionCount(UUID fileId) {
    return jdbc.queryForObject(
        "SELECT count(*)::int FROM pg_class WHERE relname = ?", Integer.class, partitionName(fileId));
  }

  private Integer foreignKeyCount(UUID fileId) {
    return jdbc.queryForObject(
        "SELECT count(*)::int FROM pg_constraint WHERE conrelid = ?::regclass AND contype = 'f'",
        Integer.class,
        partitionName(fileId));
  }

  private Integer packetCount(UUID fileId) {
    return jdbc.queryForObject(
        "SELECT count(*)::int FROM packets WHERE file_id = ?", Integer.class, fileId);
  }

  private boolean fileExists(UUID fileId) {
    Integer n =
        jdbc.queryForObject(
            "SELECT count(*)::int FROM files WHERE id = ?", Integer.class, fileId);
    return n != null && n > 0;
  }
}
