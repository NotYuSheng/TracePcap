package com.tracepcap.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.governance.RoleEntity;
import com.tracepcap.governance.RoleRepository;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * V72 seeds the four built-in roles from the catalogue, keeping the levels the ten older actions
 * had, so an upgrade changes nothing an analyst could already do. Seeding is SQL, so it's checked
 * against a real database.
 */
@SpringBootTest
@Testcontainers
class RolesMigrationIntegrationTest {

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

  @Autowired RoleRepository roles;

  @Test
  void seedsTheFourBuiltInRoles_withAnalystAsTheDefault() {
    List<RoleEntity> all = roles.findAllByOrderByPositionDescKeyAsc();
    assertThat(all).extracting(RoleEntity::getKey).containsExactly("admin", "lead", "analyst", "viewer");
    assertThat(roles.findFirstByDefaultRoleTrue()).get().extracting(RoleEntity::getKey).isEqualTo("analyst");

    Map<String, java.util.Set<String>> perms =
        all.stream().collect(Collectors.toMap(RoleEntity::getKey, RoleEntity::getPermissions));
    assertThat(perms.get("viewer")).containsExactlyInAnyOrder("SEE_CAPTURES", "DOWNLOAD_REPORT");
    // The ten older actions keep their default level: analyst can still edit global rules...
    assertThat(perms.get("analyst")).contains("DETECTION_RULES_GLOBAL", "ADDRESS_DEFAULTS", "ANALYSIS_POLICY");
    // ...but not what was admin-only, nor the new lead-level checks.
    assertThat(perms.get("analyst")).doesNotContain("RETENTION", "LLM_CONNECTION", "READ_AUDIT_LOG", "DELETE_ANY_CAPTURES");
    assertThat(perms.get("lead")).contains("READ_AUDIT_LOG", "DELETE_ANY_CAPTURES", "NETWORK_DELETE");
    assertThat(perms.get("lead")).doesNotContain("RETENTION", "LLM_CONNECTION");
    assertThat(perms.get("admin")).as("admin has everything without a stored list").isEmpty();
  }
}
