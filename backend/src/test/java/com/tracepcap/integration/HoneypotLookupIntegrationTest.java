package com.tracepcap.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.HostOpenings;
import com.tracepcap.analysis.spi.ConversationLookup.Opening;
import com.tracepcap.analysis.spi.ConversationLookup.ServerCertificate;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
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
 * The honeypot report's narrow reads (#1326): one host's openings, who opened conversations to a
 * decoy, and each server's distinct certificates, all counted in the database.
 */
@SpringBootTest
@Testcontainers
class HoneypotLookupIntegrationTest {

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
  @Autowired private ConversationLookup lookup;

  private static final String DECOY = "198.51.100.22";

  private UUID file() {
    UUID file = UUID.randomUUID();
    jdbc.update(
        "INSERT INTO files (id, file_name, file_size, minio_path, uploaded_at, status) VALUES (?, ?, 1, ?, ?, 'COMPLETED')",
        file, "f.pcap", "f.pcap", LocalDateTime.now());
    return file;
  }

  /** One conversation, stored src → dst, opened by {@code initiator} (null: unknown). */
  private void conv(UUID file, String src, int srcPort, String dst, int dstPort, String initiator,
      String subject, String issuer) {
    jdbc.update(
        "INSERT INTO conversations (id, file_id, src_ip, src_port, dst_ip, dst_port, protocol,"
            + " start_time, end_time, initiator_ip, tls_subject, tls_issuer)"
            + " VALUES (?, ?, ?, ?, ?, ?, 'TCP', now(), now(), ?, ?, ?)",
        UUID.randomUUID(), file, src, srcPort, dst, dstPort, initiator, subject, issuer);
  }

  @Test
  void oneHostsOpeningsAreCountedWhicheverWayRoundTheyWereStored() {
    UUID file = file();
    conv(file, "61.0.0.1", 40001, DECOY, 22, "61.0.0.1", null, null);
    conv(file, DECOY, 23, "61.0.0.2", 40002, "61.0.0.2", null, null); // stored reversed
    conv(file, "61.0.0.2", 40003, DECOY, 445, "61.0.0.2", null, null);
    conv(file, DECOY, 5000, "203.0.113.9", 53, DECOY, null, null); // it opened this one
    conv(file, DECOY, 5001, "10.0.0.53", 53, null, null, null); // UDP: opener unknown
    conv(file, "61.0.0.3", 1, "61.0.0.4", 2, "61.0.0.3", null, null); // not this host

    assertThat(lookup.hostOpenings(file, DECOY)).isEqualTo(new HostOpenings(1, 3, 2, 3));
    assertThat(lookup.distinctAnsweredPorts(file, DECOY)).isEqualTo(3);
    assertThat(lookup.hostOpenings(file, "192.0.2.1")).isEqualTo(new HostOpenings(0, 0, 0, 0));
  }

  @Test
  void openingsToADecoyNameWhoOpenedThemAndSkipAnUnknownOpener() {
    UUID file = file();
    conv(file, "61.0.0.1", 40001, DECOY, 22, "61.0.0.1", null, null);
    conv(file, "61.0.0.1", 40002, DECOY, 23, "61.0.0.1", null, null);
    conv(file, DECOY, 445, "61.0.0.2", 40003, "61.0.0.2", null, null);
    conv(file, DECOY, 5000, "203.0.113.9", 53, DECOY, null, null);
    conv(file, DECOY, 5001, "10.0.0.53", 53, null, null, null);
    conv(file, "61.0.0.3", 1, "61.0.0.4", 2, "61.0.0.3", null, null);

    assertThat(lookup.openingsTo(file, Set.of(DECOY))).containsExactlyInAnyOrder(
        // not the decoy's own outbound conversation
        new Opening("61.0.0.1", DECOY, 2), new Opening("61.0.0.2", DECOY, 1));
    assertThat(lookup.openingsTo(file, Set.of())).isEmpty();
  }

  @Test
  void eachServerCertificateOnceOnTheSideThatAnswered() {
    UUID file = file();
    conv(file, "10.0.0.5", 50000, DECOY, 443, "10.0.0.5", "CN=a", "O=dionaea.carnivore.it");
    conv(file, "10.0.0.6", 50001, DECOY, 443, "10.0.0.6", "CN=a", "O=dionaea.carnivore.it");
    conv(file, DECOY, 8443, "10.0.0.7", 50002, "10.0.0.7", "CN=b", "O=x"); // stored reversed
    conv(file, "10.0.0.8", 50003, "192.0.2.1", 443, null, null, "CN=c"); // no opener: destination
    conv(file, "10.0.0.8", 50005, "192.0.2.3", 443, "10.0.0.8", "CN=d", null); // no issuer
    conv(file, "10.0.0.9", 50004, "192.0.2.2", 80, "10.0.0.9", null, null); // no certificate

    assertThat(lookup.serverCertificates(file)).containsExactly(
        new ServerCertificate("192.0.2.1", 443, null, "CN=c"),
        new ServerCertificate(DECOY, 443, "CN=a", "O=dionaea.carnivore.it"),
        new ServerCertificate(DECOY, 8443, "CN=b", "O=x"));
    assertThat(lookup.serverCertificates(file, DECOY)).extracting(ServerCertificate::port)
        .containsExactly(443, 8443);
    assertThat(lookup.serverCertificates(file, "10.0.0.7")).isEmpty();
  }
}
