package com.tracepcap.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.file.service.FileService;
import java.time.LocalDateTime;
import java.util.List;
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
 * Deleting a monitor snapshot's file keeps the network's snapshot history consistent (#635).
 *
 * <p>Retention (MONITOR_FILE_RETENTION_HOURS) and a manual delete from the files list both remove
 * the file through {@code FileService.deleteFile}, and the snapshot row goes with it by FK cascade.
 * Only a UI "remove snapshot" used to close the gap in snapshot_order and re-run change detection.
 * So the other paths left gaps, plus change events whose from_snapshot_id the cascade had set to
 * NULL: drift reported between a snapshot that no longer exists and one that does.
 */
@SpringBootTest
@Testcontainers
class MonitorSnapshotFileDeletionIntegrationTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(DockerImageName.parse("postgres:15-alpine"));

  // Chainguard MinIO, as in the other integration tests (MinIO's own images are gone).
  @Container
  static final GenericContainer<?> MINIO =
      new GenericContainer<>(DockerImageName.parse("cgr.dev/chainguard/minio:latest"))
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

  @Autowired private JdbcTemplate jdbc;
  @Autowired private FileService fileService;
  @Autowired private com.tracepcap.file.service.StorageService storage;

  @Test
  void deletingTheMiddleSnapshotsFile_closesTheGapAndLeavesNoDanglingChangeEvents() {
    UUID network = UUID.randomUUID();
    jdbc.update("INSERT INTO networks (id, name) VALUES (?, ?)", network, "net-" + network);
    LocalDateTime t0 = LocalDateTime.now().minusDays(3);
    UUID s0 = snapshot(network, monitorFile(t0), 0);
    UUID s1 = snapshot(network, monitorFile(t0.plusDays(1)), 1);
    UUID s2 = snapshot(network, monitorFile(t0.plusDays(2)), 2);
    // Change events as the chain would have left them: 0 -> 1 and 1 -> 2.
    changeEvent(network, s0, s1);
    changeEvent(network, s1, s2);

    UUID middleFile =
        jdbc.queryForObject("SELECT file_id FROM network_snapshots WHERE id = ?", UUID.class, s1);
    fileService.deleteFile(middleFile); // the path retention and the files list both use

    List<Integer> orders =
        jdbc.queryForList(
            "SELECT snapshot_order FROM network_snapshots WHERE network_id = ? ORDER BY snapshot_order",
            Integer.class,
            network);
    assertThat(orders).as("no gap where the deleted snapshot was").containsExactly(0, 1);
    assertThat(
            jdbc.queryForObject(
                "SELECT count(*) FROM network_change_events WHERE network_id = ?"
                    + " AND (from_snapshot_id IS NULL OR from_snapshot_id NOT IN"
                    + " (SELECT id FROM network_snapshots WHERE network_id = ?))",
                Integer.class,
                network,
                network))
        .as("no change event describes drift from a snapshot that no longer exists")
        .isZero();
  }

  private UUID monitorFile(LocalDateTime start) {
    UUID id = UUID.randomUUID();
    // A real object, so deleteFile's storage step succeeds and the delete reaches the DB cascade.
    try {
      java.io.File tmp = java.io.File.createTempFile("snap-", ".pcap");
      tmp.deleteOnExit();
      storage.uploadFile(tmp, id + ".pcap", "application/vnd.tcpdump.pcap");
    } catch (java.io.IOException e) {
      throw new IllegalStateException(e);
    }
    jdbc.update(
        "INSERT INTO files (id, file_name, file_size, minio_path, uploaded_at, status, source,"
            + " start_time) VALUES (?, ?, ?, ?, ?, 'COMPLETED', 'MONITOR', ?)",
        id,
        id + ".pcap",
        1024L,
        id + ".pcap",
        start,
        start);
    return id;
  }

  private UUID snapshot(UUID network, UUID file, int order) {
    UUID id = UUID.randomUUID();
    jdbc.update(
        "INSERT INTO network_snapshots (id, network_id, file_id, snapshot_order) VALUES (?, ?, ?, ?)",
        id,
        network,
        file,
        order);
    return id;
  }

  private void changeEvent(UUID network, UUID from, UUID to) {
    jdbc.update(
        "INSERT INTO network_change_events (network_id, from_snapshot_id, to_snapshot_id,"
            + " change_type, entity_type, entity_key) VALUES (?, ?, ?, 'MAC_ADDED', 'DEVICE', 'aa:bb:cc:dd:ee:ff')",
        network,
        from,
        to);
  }
}
