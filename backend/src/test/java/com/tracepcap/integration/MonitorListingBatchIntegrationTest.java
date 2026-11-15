package com.tracepcap.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.monitor.dto.NetworkDto;
import com.tracepcap.monitor.dto.NetworkSnapshotDto;
import com.tracepcap.monitor.service.NetworkService;
import com.tracepcap.monitor.service.SnapshotService;
import com.tracepcap.subnets.dto.SubnetOverlapWarningDto;
import com.tracepcap.subnets.service.SubnetOverlapDetectionService;
import java.util.Map;
import java.util.stream.Collectors;
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
 * The monitor listings and overlap detection batch their per-row queries (#469), and still return
 * the same answers. The networks list used to run four queries per network, the snapshots list one
 * insight check per row, and overlap detection one conflict query per snapshot. This pins what
 * they return against a real database, since the batched versions are grouped SQL that a mock
 * can't check.
 */
@SpringBootTest
@Testcontainers
class MonitorListingBatchIntegrationTest {

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
  @Autowired private NetworkService networkService;
  @Autowired private SnapshotService snapshotService;
  @Autowired private SubnetOverlapDetectionService overlapDetection;

  @Test
  void networksList_countsAndInsightFlagsPerNetwork() {
    UUID busy = network("busy");
    UUID quiet = network("quiet");
    UUID s0 = snapshot(busy, file(), 0);
    UUID s1 = snapshot(busy, file(), 1);
    snapshot(quiet, file(), 0);
    event(busy, s0, s1, "CRITICAL", false);
    event(busy, s0, s1, "CRITICAL", false);
    event(busy, s0, s1, "CRITICAL", true); // reviewed: not counted
    event(busy, s0, s1, "WARNING", false);
    event(busy, s0, s1, "INFO", false); // neither critical nor warning
    jdbc.update("INSERT INTO network_insights (network_id) VALUES (?)", busy);

    Map<UUID, NetworkDto> byId =
        networkService.getAllNetworks().stream().collect(Collectors.toMap(NetworkDto::getId, n -> n));

    NetworkDto b = byId.get(busy);
    assertThat(b.getSnapshotCount()).isEqualTo(2);
    assertThat(b.getCriticalChanges()).isEqualTo(2);
    assertThat(b.getWarningChanges()).isEqualTo(1);
    assertThat(b.isHasInsights()).isTrue();
    NetworkDto q = byId.get(quiet);
    assertThat(q.getSnapshotCount()).isEqualTo(1);
    assertThat(q.getCriticalChanges()).isZero();
    assertThat(q.getWarningChanges()).isZero();
    assertThat(q.isHasInsights()).isFalse();
    // The single-network path shares the batched mapping.
    assertThat(networkService.getNetwork(busy)).isEqualTo(b);
  }

  @Test
  void snapshotsList_insightFlagPerSnapshot() {
    UUID net = network("snaps");
    UUID s0 = snapshot(net, file(), 0);
    UUID s1 = snapshot(net, file(), 1);
    jdbc.update("INSERT INTO snapshot_insights (snapshot_id) VALUES (?)", s1);

    Map<UUID, Boolean> flags =
        snapshotService.listSnapshots(net).stream()
            .collect(Collectors.toMap(NetworkSnapshotDto::getId, NetworkSnapshotDto::isHasInsights));

    assertThat(flags).containsEntry(s0, false).containsEntry(s1, true);
  }

  @Test
  void overlapDetection_findsTheEarliestSnapshotWithAConflict_acrossFilesInOneQuery() {
    UUID net = network("overlap");
    UUID clean = file();
    UUID dirty = file();
    snapshot(net, clean, 0);
    snapshot(net, dirty, 1);
    observe(clean, "10.99.0.5", "aa:aa:aa:aa:aa:01");
    observe(dirty, "10.99.0.5", "aa:aa:aa:aa:aa:01");
    observe(dirty, "10.99.0.5", "bb:bb:bb:bb:bb:02"); // same IP, second MAC: a conflict
    observe(dirty, "10.99.0.6", "cc:cc:cc:cc:cc:03");
    jdbc.update("INSERT INTO subnet_definitions (cidr) VALUES ('10.99.0.0/24') ON CONFLICT DO NOTHING");

    List<SubnetOverlapWarningDto> warnings =
        overlapDetection.detect(net).stream().filter(w -> "10.99.0.0/24".equals(w.getCidr())).toList();

    assertThat(warnings).hasSize(1);
    assertThat(warnings.get(0).getConflictingIp()).isEqualTo("10.99.0.5");
    assertThat(warnings.get(0).getMacs()).containsExactly("aa:aa:aa:aa:aa:01", "bb:bb:bb:bb:bb:02");
    assertThat(warnings.get(0).getSnapshotOrder()).isEqualTo(1);
  }

  private UUID network(String name) {
    UUID id = UUID.randomUUID();
    jdbc.update("INSERT INTO networks (id, name) VALUES (?, ?)", id, name + "-" + id);
    return id;
  }

  private UUID file() {
    UUID id = UUID.randomUUID();
    jdbc.update(
        "INSERT INTO files (id, file_name, file_size, minio_path, uploaded_at, status, source,"
            + " start_time) VALUES (?, ?, 1024, ?, ?, 'COMPLETED', 'MONITOR', ?)",
        id, id + ".pcap", id + ".pcap", LocalDateTime.now(), LocalDateTime.now());
    return id;
  }

  private UUID snapshot(UUID network, UUID file, int order) {
    UUID id = UUID.randomUUID();
    jdbc.update(
        "INSERT INTO network_snapshots (id, network_id, file_id, snapshot_order) VALUES (?, ?, ?, ?)",
        id, network, file, order);
    return id;
  }

  private void event(UUID network, UUID from, UUID to, String severity, boolean reviewed) {
    jdbc.update(
        "INSERT INTO network_change_events (network_id, from_snapshot_id, to_snapshot_id,"
            + " change_type, entity_type, entity_key, severity, reviewed)"
            + " VALUES (?, ?, ?, 'MAC_ADDED', 'DEVICE', ?, ?, ?)",
        network, from, to, UUID.randomUUID().toString(), severity, reviewed);
  }

  private void observe(UUID file, String ip, String mac) {
    jdbc.update("INSERT INTO ip_mac_observations (file_id, ip, mac) VALUES (?, ?, ?)", file, ip, mac);
  }
}
