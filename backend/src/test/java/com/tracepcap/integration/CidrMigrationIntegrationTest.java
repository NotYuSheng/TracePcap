package com.tracepcap.integration;

import static org.assertj.core.api.Assertions.assertThat;

import db.migration.V86__normalise_saved_cidrs;
import java.sql.Connection;
import javax.sql.DataSource;
import org.flywaydb.core.api.migration.Context;
import org.mockito.Mockito;
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
 * V86 (#1351) moves CIDRs saved before the shared normaliser onto what a save writes now, without
 * ever failing the upgrade. V87 (#1354) gives SQL one CIDR test for both families, {@code ip_inet}.
 */
@SpringBootTest
@Testcontainers
class CidrMigrationIntegrationTest {

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
  @Autowired private DataSource dataSource;

  /** Runs V86 again over rows written the old way: it is idempotent, so a second run is safe. */
  private void migrate() throws Exception {
    try (Connection c = dataSource.getConnection()) {
      Context ctx = Mockito.mock(Context.class);
      Mockito.when(ctx.getConnection()).thenReturn(c);
      new V86__normalise_saved_cidrs().migrate(ctx);
    }
  }

  private List<String> cidrs(String table, String label) {
    return jdbc.queryForList("SELECT cidr FROM " + table + " WHERE label LIKE ? ORDER BY id", String.class, label);
  }

  @Test
  void oldSpellingsBecomeWhatASaveWrites_butTwoSpellingsOfOneNetworkAreLeftAlone() throws Exception {
    jdbc.update("INSERT INTO subnet_definitions (cidr, label) VALUES ('10.61.2.3/24', 'm-a')");
    jdbc.update("INSERT INTO subnet_definitions (cidr, label) VALUES ('10.62.0.9/24', 'm-b1')");
    jdbc.update("INSERT INTO subnet_definitions (cidr, label) VALUES ('10.62.0.0/24', 'm-b2')"); // same network
    jdbc.update("INSERT INTO custom_private_ranges (cidr, classification) VALUES ('fd00:0:0:0:0:0:0:0/8', 'PRIVATE')");
    jdbc.update("INSERT INTO ip_org_rules (label, cidr, prefix_length) VALUES ('m-org', ' 203.0.113.9/24 ', 24)");
    jdbc.update("INSERT INTO ip_org_rules (label, cidr, prefix_length) VALUES ('m-free', 'gw.corp/24', 24)");

    migrate();

    assertThat(cidrs("subnet_definitions", "m-a")).containsExactly("10.61.2.0/24");
    // Both spellings of 10.62.0.0/24 stay: which to keep is the operator's call, and rewriting
    // one onto the other would break the unique index.
    assertThat(cidrs("subnet_definitions", "m-b%")).containsExactly("10.62.0.9/24", "10.62.0.0/24");
    assertThat(jdbc.queryForList("SELECT cidr FROM custom_private_ranges", String.class)).contains("fd00::/8");
    assertThat(cidrs("ip_org_rules", "m-org")).containsExactly("203.0.113.0/24");
    assertThat(cidrs("ip_org_rules", "m-free")).containsExactly("gw.corp/24");

    migrate(); // nothing left to do
    assertThat(cidrs("subnet_definitions", "m-a")).containsExactly("10.61.2.0/24");
  }

  @Test
  void aNetworkContestedInTheDefaultIsLeftAsSavedInEveryListThatJoinsToIt() throws Exception {
    UUID net = UUID.randomUUID();
    jdbc.update("INSERT INTO networks (id, name) VALUES (?, 'm-net')", net);
    jdbc.update("INSERT INTO custom_private_ranges (cidr, classification) VALUES ('10.70.0.9/16', 'PRIVATE')");
    jdbc.update("INSERT INTO custom_private_ranges (cidr, classification) VALUES ('10.70.0.0/16', 'PUBLIC')");
    // Alone in its network's list, but the default it overrides is contested: rewriting it would
    // stop it matching either default spelling.
    jdbc.update("INSERT INTO custom_private_ranges (cidr, classification, network_id) VALUES ('10.70.5.5/16', 'PRIVATE', ?)", net);
    jdbc.update("INSERT INTO custom_private_ranges (cidr, classification, network_id) VALUES ('10.71.5.5/16', 'PRIVATE', ?)", net);

    migrate();

    assertThat(jdbc.queryForList("SELECT cidr FROM custom_private_ranges WHERE network_id = ? ORDER BY id", String.class, net))
        .containsExactly("10.70.5.5/16", "10.71.0.0/16");
  }

  private Boolean inside(String ip, String cidr) {
    return jdbc.queryForObject("SELECT ip_inet(?) <<= CAST(? AS inet)", Boolean.class, ip, cidr);
  }

  @Test
  void ipInetPutsAnAddressOfEitherFamilyInItsSubnet() {
    assertThat(inside("10.1.2.9", "10.1.2.0/24")).isTrue();
    assertThat(inside("10.1.3.9", "10.1.2.0/24")).isFalse();
    assertThat(inside("fd00::1:0:0:0:9", "fd00:0:0:1::/64")).isTrue();
    assertThat(inside("fe80::1%eth0", "fe80::/10")).isTrue();
    assertThat(inside("10.0.0.1", "::/0")).isFalse(); // never across families
    // Not an address: NULL, so never inside, and the query doesn't fail.
    for (String bad : new String[] {"aa:bb:cc:dd:ee:ff", "1:2", "10.0.0.256", "host.local", ""}) {
      assertThat(jdbc.queryForObject("SELECT ip_inet(?) IS NULL", Boolean.class, bad)).as(bad).isTrue();
    }
    assertThat(jdbc.queryForObject("SELECT to_regprocedure('ip_to_int(text)') IS NULL", Boolean.class)).isTrue();
  }
}
