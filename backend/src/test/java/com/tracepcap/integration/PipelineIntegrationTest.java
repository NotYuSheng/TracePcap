package com.tracepcap.integration;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.InputStream;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

/**
 * Full-context integration tests for the API pipeline: the real Spring Boot app on a random port,
 * backed by a Testcontainers Postgres (Flyway-migrated on boot) and MinIO. Exercises the HTTP →
 * service → repository / object-store seams, plus the standardized REST envelopes ({@code
 * PagedResponse}, {@code ErrorResponse}) and the error/validation paths.
 *
 * <p>The analysis pipeline (tshark/nDPI/Suricata) needs external binaries that only exist in the
 * backend Docker image, so these tests stop at the upload/persistence boundary. Asserting the async
 * {@code 202 → 200} analysis-completion path belongs in a container-level IT (follow-up), where the
 * toolchain is present.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class PipelineIntegrationTest {

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>(DockerImageName.parse("postgres:15-alpine"));

  @Container
  static final GenericContainer<?> MINIO =
      new GenericContainer<>(DockerImageName.parse("minio/minio:latest"))
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
    // application.yml defaults this to the SpEL literal #{null}, which @ConfigurationProperties
    // binding (unlike @Value) does not evaluate — so it must be set explicitly for tests. The LLM
    // is never exercised here; this is just a parseable stub so the context can boot.
    registry.add("llm.api.context-length", () -> "8192");
  }

  @Autowired private TestRestTemplate rest;

  @Test
  void filesList_returnsPagedResponseEnvelope() {
    ResponseEntity<JsonNode> res =
        rest.getForEntity("/api/v1/files?page=1&pageSize=5", JsonNode.class);

    assertThat(res.getStatusCode()).isEqualTo(HttpStatus.OK);
    JsonNode body = res.getBody();
    assertThat(body).isNotNull();
    assertThat(body.get("data").isArray()).isTrue();
    assertThat(body.get("page").asInt()).isEqualTo(1);
    assertThat(body.get("pageSize").asInt()).isEqualTo(5);
    assertThat(body.has("total")).isTrue();
    assertThat(body.has("totalPages")).isTrue();
  }

  @Test
  void unknownFile_returns404ErrorEnvelope() {
    ResponseEntity<JsonNode> res =
        rest.getForEntity("/api/v1/files/" + UUID.randomUUID(), JsonNode.class);

    assertThat(res.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    JsonNode body = res.getBody();
    assertThat(body).isNotNull();
    assertThat(body.get("status").asInt()).isEqualTo(404);
    assertThat(body.get("error").asText()).isEqualTo("Not Found");
    assertThat(body.hasNonNull("message")).isTrue();
    assertThat(body.get("path").asText()).contains("/api/v1/files/");
  }

  @Test
  void createNetwork_blankBody_returns400WithValidationErrors() {
    ResponseEntity<JsonNode> res =
        rest.postForEntity("/api/v1/monitor/networks", json("{}"), JsonNode.class);

    assertThat(res.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    JsonNode body = res.getBody();
    assertThat(body).isNotNull();
    assertThat(body.get("status").asInt()).isEqualTo(400);
    assertThat(body.path("validationErrors").has("name")).isTrue();
  }

  @Test
  void networkCrudLifecycle_createReadUpdateDelete() {
    ResponseEntity<JsonNode> created =
        rest.postForEntity(
            "/api/v1/monitor/networks", json("{\"name\":\"itest-net\"}"), JsonNode.class);
    assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    String id = created.getBody().get("id").asText();
    assertThat(id).isNotBlank();

    ResponseEntity<JsonNode> got =
        rest.getForEntity("/api/v1/monitor/networks/" + id, JsonNode.class);
    assertThat(got.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(got.getBody().get("name").asText()).isEqualTo("itest-net");

    ResponseEntity<JsonNode> patched =
        rest.exchange(
            "/api/v1/monitor/networks/" + id,
            HttpMethod.PATCH,
            json("{\"name\":\"itest-net-renamed\"}"),
            JsonNode.class);
    assertThat(patched.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(patched.getBody().get("name").asText()).isEqualTo("itest-net-renamed");

    ResponseEntity<Void> deleted =
        rest.exchange("/api/v1/monitor/networks/" + id, HttpMethod.DELETE, null, Void.class);
    assertThat(deleted.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);

    ResponseEntity<JsonNode> afterDelete =
        rest.getForEntity("/api/v1/monitor/networks/" + id, JsonNode.class);
    assertThat(afterDelete.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
  }

  @Test
  void uploadPcap_persistsFileAndIsRetrievable() {
    // 201 on a fresh container; 409 if another test in this class already stored this pcap.
    ResponseEntity<JsonNode> upload = uploadFixture("ftp.pcap");
    assertThat(upload.getStatusCode()).isIn(HttpStatus.CREATED, HttpStatus.CONFLICT);
    JsonNode uploadBody = upload.getBody();
    assertThat(uploadBody).isNotNull();
    String fileId =
        upload.getStatusCode() == HttpStatus.CREATED
            ? uploadBody.get("fileId").asText()
            : uploadBody.get("existingFileId").asText();
    assertThat(fileId).isNotBlank();

    ResponseEntity<JsonNode> meta = rest.getForEntity("/api/v1/files/" + fileId, JsonNode.class);
    assertThat(meta.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(meta.getBody().get("fileName").asText()).contains("ftp");
  }

  @Test
  void uploadSamePcapTwice_returns409Conflict() {
    ResponseEntity<JsonNode> first = uploadFixture("ftp.pcap");
    // Either freshly created here, or already present from another test in this class.
    assertThat(first.getStatusCode()).isIn(HttpStatus.CREATED, HttpStatus.CONFLICT);

    ResponseEntity<JsonNode> second = uploadFixture("ftp.pcap");
    assertThat(second.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    assertThat(second.getBody()).isNotNull();
    assertThat(second.getBody().get("status").asInt()).isEqualTo(409);
    assertThat(second.getBody().hasNonNull("existingFileId")).isTrue();
  }

  @Test
  void uploadNonPcapFilename_returns422() {
    ResponseEntity<JsonNode> res = uploadBytes("notes.txt", "not a pcap".getBytes());

    assertThat(res.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_ENTITY);
    assertThat(res.getBody()).isNotNull();
    assertThat(res.getBody().get("status").asInt()).isEqualTo(422);
    assertThat(res.getBody().get("error").asText()).isEqualTo("Unprocessable Entity");
  }

  @Test
  void constraintViolationOnQueryParam_returns400() {
    // TimelineController is @Validated with @Min(1) on `interval`; interval=0 is rejected by the
    // ConstraintViolationException handler before the service (and DB) are touched.
    ResponseEntity<JsonNode> res =
        rest.getForEntity("/api/v1/timeline/" + UUID.randomUUID() + "?interval=0", JsonNode.class);

    assertThat(res.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(res.getBody()).isNotNull();
    assertThat(res.getBody().get("status").asInt()).isEqualTo(400);
    assertThat(res.getBody().path("validationErrors").has("interval")).isTrue();
  }

  private ResponseEntity<JsonNode> uploadFixture(String resourceName) {
    try (InputStream in = getClass().getResourceAsStream("/fixtures/" + resourceName)) {
      assertThat(in).as("fixture /fixtures/" + resourceName).isNotNull();
      return uploadBytes(resourceName, in.readAllBytes());
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private ResponseEntity<JsonNode> uploadBytes(String filename, byte[] bytes) {
    MultiValueMap<String, Object> form = new LinkedMultiValueMap<>();
    form.add(
        "file",
        new ByteArrayResource(bytes) {
          @Override
          public String getFilename() {
            return filename;
          }
        });
    form.add("enableNdpi", "false");
    form.add("enableSuricata", "false");
    form.add("enableFileExtraction", "false");
    form.add("source", "ANALYSIS");

    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.MULTIPART_FORM_DATA);
    return rest.postForEntity("/api/v1/files", new HttpEntity<>(form, headers), JsonNode.class);
  }

  private static HttpEntity<String> json(String body) {
    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.APPLICATION_JSON);
    return new HttpEntity<>(body, headers);
  }
}
