package com.tracepcap.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.IpMacObservationLookup;
import com.tracepcap.analysis.spi.IpMacObservationLookup.IpMacs;
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
 * The ip / mac scoped observation lookups (#469) return what the whole-file lookup would, filtered:
 * the entity-detail snapshot history used to fetch every observation in the file for each snapshot
 * and filter client-side.
 */
@SpringBootTest
@Testcontainers
class IpMacObservationLookupIntegrationTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(DockerImageName.parse("postgres:15-alpine"));

  // Image source: Chainguard, NOT Docker Hub or quay.io. MinIO removed its community images from
  // every public registry in 2026 (Docker Hub deleted minio/minio; the quay.io/minio repos were made
  // private and now return "unauthorized"), so the old tags no longer pull on a clean CI runner.
  // cgr.dev/chainguard/minio is a drop-in server that pulls anonymously. The distroless `:latest` is
  // enough here — Testcontainers polls /minio/health/ready over HTTP from the host, so no in-container
  // curl/shell is needed (the compose stack uses the `-dev` variant for its own healthcheck). Floating
  // tag, not a digest: Chainguard's free tier serves only `:latest` and garbage-collects old digests.
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
  @Autowired private IpMacObservationLookup lookup;

  @Test
  void scopedLookups_matchTheWholeFileLookupFiltered() {
    UUID file = UUID.randomUUID();
    jdbc.update(
        "INSERT INTO files (id, file_name, file_size, minio_path, uploaded_at, status) VALUES (?, ?, 1, ?, ?, 'COMPLETED')",
        file, "f.pcap", "f.pcap", LocalDateTime.now());
    observe(file, "10.0.0.1", "AA:AA:AA:AA:AA:01");
    observe(file, "10.0.0.1", "bb:bb:bb:bb:bb:02"); // a second MAC on .1
    observe(file, "10.0.0.2", "aa:aa:aa:aa:aa:01"); // same device, another IP
    observe(file, "10.0.0.3", "cc:cc:cc:cc:cc:03"); // unrelated

    assertThat(lookup.ipMacObservationsForIp(file, "10.0.0.1"))
        .containsExactly(new IpMacs("10.0.0.1", List.of("AA:AA:AA:AA:AA:01", "bb:bb:bb:bb:bb:02")));

    // The IPs this MAC claimed, matched case-insensitively, each with all of its MACs.
    assertThat(lookup.ipMacObservationsForMac(file, "aa:aa:aa:aa:aa:01"))
        .containsExactly(
            new IpMacs("10.0.0.1", List.of("AA:AA:AA:AA:AA:01", "bb:bb:bb:bb:bb:02")),
            new IpMacs("10.0.0.2", List.of("aa:aa:aa:aa:aa:01")));

    assertThat(lookup.ipMacObservationsForIp(file, "10.9.9.9")).isEmpty();
    assertThat(lookup.ipMacObservations(file)).hasSize(3);
  }

  private void observe(UUID file, String ip, String mac) {
    jdbc.update("INSERT INTO ip_mac_observations (file_id, ip, mac) VALUES (?, ?, ?)", file, ip, mac);
  }
}
