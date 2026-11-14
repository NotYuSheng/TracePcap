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

  @Autowired private TestRestTemplate rest;
  @Autowired private com.tracepcap.analysis.service.ExtractionRunService extractionRunService;
  @Autowired private com.tracepcap.extraction.repository.ExtractedFileRepository extractedFiles;
  @Autowired private com.tracepcap.file.repository.FileRepository files;
  @Autowired private org.springframework.jdbc.core.JdbcTemplate jdbc;
  @Autowired private com.tracepcap.story.service.FindingsService storyFindings;

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
  void extractionRunRecord_twiceForSameFileAndExtractor_updatesInPlace() {
    // Re-analysis records the same (file, extractor) again. The naive delete-then-insert dies on
    // the unique constraint (IDENTITY ids flush the INSERT before the queued DELETE), and the
    // recorder's catch would swallow it — so assert the second write actually lands.
    UUID fileId = UUID.fromString(uploadedFileId());

    extractionRunService.record(
        fileId,
        com.tracepcap.analysis.spi.ExtractionManifest.NDPI,
        com.tracepcap.analysis.spi.ExtractionManifest.Status.FAILED,
        "first run: crashed");
    extractionRunService.record(
        fileId,
        com.tracepcap.analysis.spi.ExtractionManifest.NDPI,
        com.tracepcap.analysis.spi.ExtractionManifest.Status.COMPLETED,
        "second run: 12 flows identified");

    var run =
        extractionRunService.runFor(fileId, com.tracepcap.analysis.spi.ExtractionManifest.NDPI);
    assertThat(run).isPresent();
    assertThat(run.get().status())
        .isEqualTo(com.tracepcap.analysis.spi.ExtractionManifest.Status.COMPLETED);
    assertThat(run.get().detail()).isEqualTo("second run: 12 flows identified");
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

  // --- extracted-file download (#630) ---------------------------------------
  //
  // The endpoint the frontend pointed at for months without reaching it: getDownloadUrl()
  // built "/api/files/..." while the route lives under "/api/v1". Nothing exercised the
  // route from either side, so the 404 was invisible until someone clicked Download.
  //
  // A route that does not exist and a route that exists but cannot find the row both answer
  // 404, so status alone proves nothing. The discriminator is the body: a mapped handler
  // throws ResourceNotFoundException and GlobalExceptionHandler renders the ErrorResponse
  // envelope, whereas an unmapped path produces Spring's bare "no handler" 404 with none of
  // those fields. Asserting the envelope is therefore asserting the route is reachable.

  @Test
  void extractedFileDownload_unknownExtraction_returns404ErrorEnvelope() {
    UUID fileId = UUID.fromString(uploadedFileId());
    UUID missing = UUID.randomUUID();

    ResponseEntity<JsonNode> response =
        rest.getForEntity(
            "/api/v1/files/" + fileId + "/extractions/" + missing + "/download", JsonNode.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    JsonNode body = response.getBody();
    assertThat(body).isNotNull();
    // Envelope fields, i.e. our handler ran — not Spring's unmapped-path 404.
    assertThat(body.has("message")).isTrue();
    assertThat(body.get("message").asText()).contains(missing.toString());
  }

  @Test
  void extractedFileDownload_withoutStoredObject_returns404ErrorEnvelope() {
    // Exercises the handler body rather than only the route: a row exists, so lookup and the
    // file-ownership check both pass, and it fails at the missing minioPath.
    UUID fileId = UUID.fromString(uploadedFileId());
    var extraction =
        extractedFiles.save(
            com.tracepcap.extraction.entity.ExtractedFileEntity.builder()
                .id(UUID.randomUUID())
                .file(files.findById(fileId).orElseThrow())
                .filename("evidence.bin")
                .mimeType("application/octet-stream")
                .minioPath(null)
                .createdAt(java.time.LocalDateTime.now())
                .build());

    ResponseEntity<JsonNode> response =
        rest.getForEntity(
            "/api/v1/files/" + fileId + "/extractions/" + extraction.getId() + "/download",
            JsonNode.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(response.getBody()).isNotNull();
    assertThat(response.getBody().get("message").asText()).contains("not available");
  }

  @Test
  void extractedFileDownload_extractionBelongingToAnotherFile_returns404() {
    // The ownership guard: a valid extraction id must not be downloadable through a different
    // file's path, which would otherwise leak another capture's extracted bytes.
    UUID fileId = UUID.fromString(uploadedFileId());
    var extraction =
        extractedFiles.save(
            com.tracepcap.extraction.entity.ExtractedFileEntity.builder()
                .id(UUID.randomUUID())
                .file(files.findById(fileId).orElseThrow())
                .filename("evidence.bin")
                .minioPath("some/object/path")
                .createdAt(java.time.LocalDateTime.now())
                .build());

    ResponseEntity<JsonNode> response =
        rest.getForEntity(
            "/api/v1/files/" + UUID.randomUUID() + "/extractions/" + extraction.getId()
                + "/download",
            JsonNode.class);

    assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
  }

  /**
   * A full analysis of a capture past the batch-flush threshold completes (#409, #750).
   *
   * <p>The pipeline flushes every {@code JPA_FLUSH_INTERVAL} (50) conversations, and
   * {@code EntityManager.flush()} throws outside a transaction. Every other fixture here has fewer
   * than 50 conversations, which is how #750 shipped a pipeline with no transaction at all: small
   * captures analysed fine. {@code many-conversations.pcap} is {@code sample-files/whatsapp.pcap}
   * (86 conversations), so this one reaches the flush. It also exercises the #409 split for real:
   * tool runs with no transaction open, then one transaction for every write.
   */
  @Test
  void analysisOfACapturePastTheFlushThreshold_completes() throws Exception {
    ResponseEntity<JsonNode> upload = uploadFixture("many-conversations.pcap");
    assertThat(upload.getStatusCode()).isIn(HttpStatus.CREATED, HttpStatus.CONFLICT);
    String fileId =
        upload.getStatusCode() == HttpStatus.CREATED
            ? upload.getBody().get("fileId").asText()
            : upload.getBody().get("existingFileId").asText();

    assertThat(awaitAnalysis(fileId)).as("analysis of an 86-conversation capture").isEqualTo("completed");
    Integer conversations =
        jdbc.queryForObject(
            "SELECT count(*) FROM conversations WHERE file_id = ?::uuid", Integer.class, fileId);
    assertThat(conversations).as("enough to have reached the batch flush").isGreaterThan(50);
  }

  /**
   * srcIp + dstIp pin one directional pair (#471), where ip is a contains-match on either end.
   * Checked against SQL on a real analysed capture: the API total equals the exact-pair count, and
   * the filter is strictly narrower than ip for a host that also talks to other peers.
   */
  @Test
  void srcAndDstIp_filterToExactlyOneDirectionalPair() throws Exception {
    ResponseEntity<JsonNode> upload = uploadFixture("many-conversations.pcap");
    String fileId =
        upload.getStatusCode() == HttpStatus.CREATED
            ? upload.getBody().get("fileId").asText()
            : upload.getBody().get("existingFileId").asText();
    assertThat(awaitAnalysis(fileId)).isEqualTo("completed");

    // The busiest source that also talks to more than one peer, and its most frequent destination.
    java.util.Map<String, Object> pair =
        jdbc.queryForMap(
            "SELECT src_ip, dst_ip, count(*) AS n FROM conversations WHERE file_id = ?::uuid"
                + " AND src_ip IN (SELECT src_ip FROM conversations WHERE file_id = ?::uuid"
                + "   GROUP BY src_ip HAVING count(DISTINCT dst_ip) > 1)"
                + " GROUP BY src_ip, dst_ip ORDER BY n DESC LIMIT 1",
            fileId,
            fileId);
    String src = (String) pair.get("src_ip");
    String dst = (String) pair.get("dst_ip");
    long exact = ((Number) pair.get("n")).longValue();

    JsonNode byPair =
        rest.getForEntity(
                "/api/v1/conversations/" + fileId + "?pageSize=500&srcIp={s}&dstIp={d}",
                JsonNode.class,
                src,
                dst)
            .getBody();
    JsonNode byIp =
        rest.getForEntity(
                "/api/v1/conversations/" + fileId + "?pageSize=500&ip={s}", JsonNode.class, src)
            .getBody();

    assertThat(byPair.get("total").asLong()).isEqualTo(exact);
    assertThat(byIp.get("total").asLong()).isGreaterThan(exact);
  }

  /**
   * Windows logins end to end (#812): a host with two accounts gets a count and no single name,
   * a host with one gets that name, and the timeline endpoint lists every login oldest first.
   * {@code windows-logons.pcap} is described in WindowsLogonRealCaptureTest.
   */
  @Test
  void windowsLogons_labelOnlyWhenOneAccount_andTimelineListsAll() throws Exception {
    ResponseEntity<JsonNode> upload = uploadFixture("windows-logons.pcap");
    String fileId =
        upload.getStatusCode() == HttpStatus.CREATED
            ? upload.getBody().get("fileId").asText()
            : upload.getBody().get("existingFileId").asText();
    assertThat(awaitAnalysis(fileId)).isEqualTo("completed");

    JsonNode hosts = rest.getForEntity("/api/v1/files/" + fileId + "/host-classifications", JsonNode.class).getBody();
    java.util.Map<String, JsonNode> byIp = new java.util.HashMap<>();
    hosts.forEach(h -> byIp.put(h.get("ip").asText(), h));

    JsonNode shared = byIp.get("10.0.0.10"); // alice, then bob
    assertThat(shared.get("loggedInUserCount").asInt()).isEqualTo(2);
    assertThat(shared.path("loggedInUser").isNull() || shared.path("loggedInUser").isMissingNode()).isTrue();
    JsonNode single = byIp.get("10.0.0.11"); // carol (the machine account doesn't count)
    assertThat(single.get("loggedInUserCount").asInt()).isEqualTo(1);
    assertThat(single.get("loggedInUser").asText()).isEqualTo("carol");

    JsonNode timeline =
        rest.getForEntity("/api/v1/files/" + fileId + "/hosts/10.0.0.10/windows-logons", JsonNode.class).getBody();
    assertThat(timeline).hasSize(2);
    assertThat(timeline.get(0).get("username").asText()).isEqualTo("alice");
    assertThat(timeline.get(1).get("username").asText()).isEqualTo("bob");
    assertThat(timeline.get(1).get("seenCount").asInt()).isEqualTo(2);

    JsonNode ldapHost =
        rest.getForEntity("/api/v1/files/" + fileId + "/hosts/10.0.0.12/windows-logons", JsonNode.class).getBody();
    java.util.List<String> folders = new java.util.ArrayList<>();
    ldapHost.forEach(l -> folders.add(l.get("username").asText() + ":" + l.get("folderKind").asText()));
    assertThat(folders).containsExactlyInAnyOrder("Clark Collier:USERS", "Dana Lee:CUSTOM");
  }

  /**
   * Per-network inactivity settings (#488): a new network starts on the default (captures, 1:
   * the behaviour before the setting existed), a valid rule is saved and returned on the network,
   * and an invalid one is a 400 with validation errors.
   */
  @Test
  void networkSettings_defaultSaveAndValidate() {
    String id =
        rest.postForEntity("/api/v1/monitor/networks", json("{\"name\":\"settings-net\"}"), JsonNode.class)
            .getBody().get("id").asText();
    String url = "/api/v1/monitor/networks/" + id + "/settings";

    JsonNode defaults = rest.getForEntity(url, JsonNode.class).getBody();
    assertThat(defaults.get("inactivityMode").asText()).isEqualTo("SNAPSHOTS");
    assertThat(defaults.get("inactivityThreshold").asInt()).isEqualTo(1);

    ResponseEntity<JsonNode> saved =
        rest.exchange(url, HttpMethod.PUT, json("{\"inactivityMode\":\"DAYS\",\"inactivityThreshold\":14}"), JsonNode.class);
    assertThat(saved.getStatusCode()).isEqualTo(HttpStatus.OK);
    JsonNode network = rest.getForEntity("/api/v1/monitor/networks/" + id, JsonNode.class).getBody();
    assertThat(network.path("settings").path("inactivityMode").asText()).isEqualTo("DAYS");
    assertThat(network.path("settings").path("inactivityThreshold").asInt()).isEqualTo(14);

    ResponseEntity<JsonNode> zero =
        rest.exchange(url, HttpMethod.PUT, json("{\"inactivityMode\":\"SNAPSHOTS\",\"inactivityThreshold\":0}"), JsonNode.class);
    assertThat(zero.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(zero.getBody().path("validationErrors").has("inactivityThreshold")).isTrue();

    ResponseEntity<JsonNode> noMode =
        rest.exchange(url, HttpMethod.PUT, json("{\"inactivityThreshold\":3}"), JsonNode.class);
    assertThat(noMode.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  /**
   * Conversation rows say who was logged in on each endpoint when they started (#812 follow-up),
   * only when unambiguous. On windows-logons.pcap: 10.0.0.10's Kerberos conversation starts with
   * alice's login (bob only arrives 5h later), 10.0.0.13's frame names two accounts at once, and
   * the domain controller 10.0.0.1 has no login of its own.
   */
  @Test
  void conversationRows_sayWhoWasLoggedInAtTheTime() throws Exception {
    ResponseEntity<JsonNode> upload = uploadFixture("windows-logons.pcap");
    String fileId =
        upload.getStatusCode() == HttpStatus.CREATED
            ? upload.getBody().get("fileId").asText()
            : upload.getBody().get("existingFileId").asText();
    assertThat(awaitAnalysis(fileId)).isEqualTo("completed");

    JsonNode rows = rest.getForEntity("/api/v1/conversations/" + fileId + "?pageSize=100", JsonNode.class)
        .getBody().get("data");
    java.util.Map<String, JsonNode> bySrc = new java.util.HashMap<>();
    rows.forEach(r -> bySrc.putIfAbsent(r.get("srcIp").asText(), r));

    JsonNode alice = bySrc.get("10.0.0.10").get("srcAccount");
    assertThat(alice.get("username").asText()).isEqualTo("alice");
    assertThat(alice.get("accountCount").asInt()).isEqualTo(1);

    JsonNode two = bySrc.get("10.0.0.13").get("srcAccount");
    assertThat(two.get("accountCount").asInt()).isEqualTo(2);
    assertThat(two.path("username").isNull() || two.path("username").isMissingNode()).isTrue();

    // The DC is the destination of these flows and logs in as nobody.
    JsonNode dc = bySrc.get("10.0.0.10").path("dstAccount");
    assertThat(dc.isNull() || dc.isMissingNode()).isTrue();
  }

  /**
   * Personal preferences with login off (#915 phase 2): one shared profile everyone reads and
   * updates, flagged as shared so the UI can say so.
   */
  @Test
  void preferences_loginOff_areOneSharedProfile() {
    String url = "/api/v1/preferences";
    rest.exchange(url, HttpMethod.PUT, json("{}"), JsonNode.class); // start clean: tests share the DB

    JsonNode empty = rest.getForEntity(url, JsonNode.class).getBody();
    assertThat(empty.get("shared").asBoolean()).isTrue();
    assertThat(empty.path("themeMode").isNull() || empty.path("themeMode").isMissingNode()).isTrue();

    ResponseEntity<JsonNode> saved =
        rest.exchange(
            url,
            HttpMethod.PUT,
            json("{\"themeMode\":\"dark\",\"conversationColumns\":[\"source\",\"users\"],"
                + "\"nodeLabelConfig\":{\"fields\":[{\"field\":\"ip\",\"enabled\":true}]}}"),
            JsonNode.class);
    assertThat(saved.getStatusCode()).isEqualTo(HttpStatus.OK);

    JsonNode back = rest.getForEntity(url, JsonNode.class).getBody();
    assertThat(back.get("themeMode").asText()).isEqualTo("dark");
    assertThat(back.get("conversationColumns")).hasSize(2);
    assertThat(back.path("nodeLabelConfig").path("fields").get(0).get("field").asText()).isEqualTo("ip");
    assertThat(back.get("shared").asBoolean()).isTrue();

    ResponseEntity<JsonNode> bad =
        rest.exchange(url, HttpMethod.PUT, json("{\"themeMode\":\"neon\"}"), JsonNode.class);
    assertThat(bad.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
  }

  /**
   * Host identity fixes from the #918 audit, on identity-cases.pcap (see identity-cases.gen.py):
   * off-subnet hosts no longer get the gateway's MAC, and broadcast / multicast / unspecified
   * addresses are not classified as hosts.
   */
  @Test
  void hostIdentity_noGatewayMacOnRoutedHosts_noHostsForNonHostAddresses() throws Exception {
    ResponseEntity<JsonNode> upload = uploadFixture("identity-cases.pcap");
    String fileId =
        upload.getStatusCode() == HttpStatus.CREATED
            ? upload.getBody().get("fileId").asText()
            : upload.getBody().get("existingFileId").asText();
    assertThat(awaitAnalysis(fileId)).isEqualTo("completed");

    JsonNode hosts = rest.getForEntity("/api/v1/files/" + fileId + "/host-classifications", JsonNode.class).getBody();
    java.util.Map<String, JsonNode> byIp = new java.util.HashMap<>();
    hosts.forEach(h -> byIp.put(h.get("ip").asText(), h));

    for (String routed : java.util.List.of("93.184.216.34", "151.101.1.69", "140.82.112.3")) {
      JsonNode mac = byIp.get(routed).path("mac");
      assertThat(mac.isNull() || mac.isMissingNode()).as("%s must not carry the gateway's MAC", routed).isTrue();
    }
    assertThat(byIp).doesNotContainKeys("0.0.0.0", "255.255.255.255", "224.0.0.18");
    // A local host keeps its own (ARP-claimed) MAC.
    assertThat(byIp.get("10.0.0.50").get("mac").asText()).isEqualTo("bb:bb:bb:00:00:01");
  }

  /**
   * Time-bounded occupancy (#918 item 3, slice 1) on identity-cases.pcap: 10.0.0.50 was the laptop
   * (ARP + DHCP as LAPTOP-ALICE), then an hour later the phone. Two occupancies, split by ARP. The
   * cloned VMs (one MAC) are one occupancy until an analyst splits them; the split is audited and
   * can be undone.
   */
  @Test
  void occupancy_splitsAReusedAddress_andAnalystsCanSplitAndUndo() throws Exception {
    ResponseEntity<JsonNode> upload = uploadFixture("identity-cases.pcap");
    String fileId =
        upload.getStatusCode() == HttpStatus.CREATED
            ? upload.getBody().get("fileId").asText()
            : upload.getBody().get("existingFileId").asText();
    assertThat(awaitAnalysis(fileId)).isEqualTo("completed");
    String base = "/api/v1/files/" + fileId + "/hosts/";

    JsonNode reused = rest.getForEntity(base + "10.0.0.50/occupancies", JsonNode.class).getBody();
    JsonNode occ = reused.get("occupancies");
    assertThat(occ).hasSize(2);
    assertThat(occ.get(0).get("mac").asText()).isEqualTo("bb:bb:bb:00:00:01");
    assertThat(occ.get(0).get("hostname").asText()).isEqualTo("LAPTOP-ALICE");
    assertThat(occ.get(1).get("mac").asText()).isEqualTo("cc:cc:cc:00:00:02");
    assertThat(occ.get(1).get("hostname").asText()).isEqualTo("iPhone-Bob");
    assertThat(occ.get(1).get("startSource").asText()).isEqualTo("arp");
    assertThat(occ.get(1).get("automatic").asBoolean()).isTrue();
    assertThat(occ.get(0).get("conversations").asLong()).isPositive();
    assertThat(occ.get(1).get("conversations").asLong()).isPositive();

    // Cloned VMs: one MAC, so one device until an analyst says otherwise.
    JsonNode clone = rest.getForEntity(base + "10.0.0.70/occupancies", JsonNode.class).getBody();
    assertThat(clone.get("occupancies")).hasSize(1);
    java.util.Map<String, Object> split = new java.util.HashMap<>();
    split.put("action", "split");
    split.put("reason", "two VMs cloned from one image");
    // The VM traffic runs from +300 s to +305 s; split at +302 s.
    java.time.LocalDateTime t0 =
        java.time.LocalDateTime.ofInstant(java.time.Instant.ofEpochSecond(1730000000L + 302), java.time.ZoneId.systemDefault());
    split.put("at", t0.toString());
    ResponseEntity<JsonNode> created = rest.postForEntity(base + "10.0.0.70/occupancy-decisions", split, JsonNode.class);
    assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    assertThat(created.getBody().get("occupancies")).hasSize(2);
    assertThat(created.getBody().get("occupancies").get(1).get("startSource").asText()).isEqualTo("manual");
    long decisionId = created.getBody().get("decisions").get(0).get("id").asLong();
    assertThat(jdbc.queryForObject(
            "SELECT count(*) FROM audit_log WHERE action = 'host-occupancy.split'", Integer.class))
        .isPositive();

    // A split with no activity on one side is refused.
    split.put("at", t0.plusDays(1).toString());
    assertThat(rest.postForEntity(base + "10.0.0.70/occupancy-decisions", split, JsonNode.class).getStatusCode())
        .isEqualTo(HttpStatus.BAD_REQUEST);

    rest.delete(base + "10.0.0.70/occupancy-decisions/" + decisionId);
    assertThat(rest.getForEntity(base + "10.0.0.70/occupancies", JsonNode.class).getBody().get("occupancies")).hasSize(1);

    // Merging the automatic boundary ("not a different device") makes 10.0.0.50 one occupancy.
    java.util.Map<String, Object> merge = new java.util.HashMap<>();
    merge.put("action", "merge");
    merge.put("reason", "same phone, private MAC rotated");
    merge.put("at", occ.get(1).get("boundaryKey").asText());
    ResponseEntity<JsonNode> merged = rest.postForEntity(base + "10.0.0.50/occupancy-decisions", merge, JsonNode.class);
    assertThat(merged.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    assertThat(merged.getBody().get("occupancies")).hasSize(1);
    rest.delete(base + "10.0.0.50/occupancy-decisions/" + merged.getBody().get("decisions").get(0).get("id").asLong());
  }

  /**
   * Per-device classification (#918 slice 2) on identity-cases.pcap: each device that held
   * 10.0.0.50 is classified from its own stretch's traffic, so the laptop keeps TTL 128 and the
   * phone gets its own 64. A manual split is classified the same way, at once.
   */
  @Test
  void occupancy_eachDeviceIsClassifiedFromItsOwnTraffic() throws Exception {
    ResponseEntity<JsonNode> upload = uploadFixture("identity-cases.pcap");
    String fileId =
        upload.getStatusCode() == HttpStatus.CREATED
            ? upload.getBody().get("fileId").asText()
            : upload.getBody().get("existingFileId").asText();
    assertThat(awaitAnalysis(fileId)).isEqualTo("completed");

    JsonNode list = rest.getForEntity("/api/v1/files/" + fileId + "/occupancies", JsonNode.class).getBody();
    JsonNode address = null;
    for (JsonNode a : list) if ("10.0.0.50".equals(a.get("ip").asText())) address = a;
    assertThat(address).as("10.0.0.50 is listed as reused").isNotNull();
    for (JsonNode a : list) assertThat(a.get("ip").asText()).isNotEqualTo("10.0.0.70"); // one MAC: not reused
    JsonNode laptop = address.get("occupancies").get(0).get("classification");
    JsonNode phone = address.get("occupancies").get(1).get("classification");
    assertThat(laptop.get("ttl").asInt()).isEqualTo(128);
    assertThat(phone.get("ttl").asInt()).isEqualTo(64);
    assertThat(laptop.get("deviceType").asText()).isNotBlank();
    assertThat(phone.get("deviceType").asText()).isNotBlank();
    assertThat(laptop.get("winnerReasons").asText()).contains("TTL 128");
    assertThat(phone.get("winnerReasons").asText()).doesNotContain("TTL 128");

    // A manual split of the cloned VMs: both halves are classified straight away.
    String base = "/api/v1/files/" + fileId + "/hosts/10.0.0.70/";
    java.util.Map<String, Object> split = new java.util.HashMap<>();
    split.put("action", "split");
    split.put("reason", "two VMs cloned from one image");
    split.put("at", java.time.LocalDateTime.ofInstant(
        java.time.Instant.ofEpochSecond(1730000000L + 302), java.time.ZoneId.systemDefault()).toString());
    ResponseEntity<JsonNode> created = rest.postForEntity(base + "occupancy-decisions", split, JsonNode.class);
    assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    JsonNode halves = created.getBody().get("occupancies");
    assertThat(halves).hasSize(2);
    assertThat(halves.get(0).get("classification").get("deviceType").asText()).isNotBlank();
    assertThat(halves.get(1).get("classification").get("deviceType").asText()).isNotBlank();
    rest.delete(base + "occupancy-decisions/" + created.getBody().get("decisions").get(0).get("id").asLong());
  }

  /**
   * Labels on one device (#918 slice 3): a label and role on the phone's key stay off the laptop,
   * the identity and evidence answer per device, and a merge moves them onto the joined device
   * while undoing it moves them back.
   */
  @Test
  void occupancy_labelsAndRolesStayOnOneDevice_andSurviveAMergeAndUndo() throws Exception {
    ResponseEntity<JsonNode> upload = uploadFixture("identity-cases.pcap");
    String fileId =
        upload.getStatusCode() == HttpStatus.CREATED
            ? upload.getBody().get("fileId").asText()
            : upload.getBody().get("existingFileId").asText();
    assertThat(awaitAnalysis(fileId)).isEqualTo("completed");
    String files = "/api/v1/files/" + fileId;
    JsonNode occ = rest.getForEntity(files + "/hosts/10.0.0.50/occupancies", JsonNode.class).getBody().get("occupancies");
    String boundary = occ.get(1).get("boundaryKey").asText();
    String phone = "10.0.0.50@" + boundary;

    rest.put(files + "/adjudications/host-identity/" + phone + "/override", json("{\"label\":\"IOT\",\"rationale\":\"visitor phone\"}"));
    rest.put("/api/v1/node-roles", json("{\"fileId\":\"" + fileId + "\",\"entityType\":\"IP\",\"entityKey\":\"" + phone
        + "\",\"roleLabel\":\"Visitor phone\",\"confirmedByHuman\":true}"));

    java.util.function.Supplier<java.util.Map<String, String>> identities = () -> {
      java.util.Map<String, String> m = new java.util.HashMap<>();
      for (JsonNode h : rest.getForEntity(files + "/host-identities", JsonNode.class).getBody()) {
        if (h.get("ip").asText().startsWith("10.0.0.50")) m.put(h.get("ip").asText(), h.get("primaryLabel").asText());
      }
      return m;
    };
    assertThat(identities.get()).containsEntry(phone, "IOT").containsKey("10.0.0.50");
    assertThat(identities.get().get("10.0.0.50")).isNotEqualTo("IOT");
    JsonNode phoneEvidence = rest.getForEntity(files + "/hosts/" + phone + "/identity", JsonNode.class).getBody();
    assertThat(phoneEvidence.get("primaryLabel").asText()).isEqualTo("IOT");
    assertThat(phoneEvidence.get("ttl").asInt()).isEqualTo(64);

    // Merge: the phone's label and role move to the joined device (the bare IP).
    java.util.Map<String, Object> merge = new java.util.HashMap<>();
    merge.put("action", "merge");
    merge.put("reason", "same device");
    merge.put("at", boundary);
    JsonNode merged = rest.postForEntity(files + "/hosts/10.0.0.50/occupancy-decisions", merge, JsonNode.class).getBody();
    assertThat(identities.get()).containsOnlyKeys("10.0.0.50").containsEntry("10.0.0.50", "IOT");
    assertThat(jdbc.queryForObject(
            "SELECT entity_key FROM node_roles WHERE file_id = ?::uuid AND role_label = 'Visitor phone'", String.class, fileId))
        .isEqualTo("10.0.0.50");

    // Undo: the phone is back, and so are its label and role.
    rest.delete(files + "/hosts/10.0.0.50/occupancy-decisions/" + merged.get("decisions").get(0).get("id").asLong());
    assertThat(identities.get()).containsEntry(phone, "IOT");
    assertThat(identities.get().get("10.0.0.50")).isNotEqualTo("IOT");
    assertThat(jdbc.queryForObject(
            "SELECT entity_key FROM node_roles WHERE file_id = ?::uuid AND role_label = 'Visitor phone'", String.class, fileId))
        .isEqualTo(phone);

    rest.delete(files + "/adjudications/host-identity/" + phone + "/override");
    jdbc.update("DELETE FROM node_roles WHERE file_id = ?::uuid AND role_label = 'Visitor phone'", fileId);
  }

  /**
   * Per-network address configuration (#915 phase 4a): a network layers its own entries on the
   * shared default per CIDR (override, add, hide), the default is unaffected, every change is
   * audited, and reverting brings the default back.
   */
  @Test
  void networkAddressConfig_layersOnTheDefault_perCidr() {
    String net =
        rest.postForEntity("/api/v1/monitor/networks", json("{\"name\":\"layer-net\"}"), JsonNode.class)
            .getBody().get("id").asText();
    String base = "/api/v1/monitor/networks/" + net;
    long rangeId = rest.postForEntity("/api/v1/custom-private-ranges",
            json("{\"cidr\":\"10.250.0.0/16\",\"classification\":\"PRIVATE\"}"), JsonNode.class)
        .getBody().get("id").asLong();
    long orgId = rest.postForEntity("/api/v1/ip-org-rules",
            json("{\"cidr\":\"10.250.0.0/16\",\"label\":\"Corp\"}"), JsonNode.class)
        .getBody().get("id").asLong();
    long subnetId = rest.postForEntity("/api/v1/subnets",
            json("{\"cidr\":\"10.250.1.0/24\",\"label\":\"Servers\"}"), JsonNode.class)
        .getBody().get("id").asLong();
    try {
      // Override the range, hide the org rule, add an org rule, override the subnet's label.
      ResponseEntity<JsonNode> r = rest.postForEntity(base + "/custom-private-ranges",
          json("{\"cidr\":\"10.250.0.0/16\",\"classification\":\"PUBLIC\"}"), JsonNode.class);
      assertThat(r.getStatusCode()).isEqualTo(HttpStatus.CREATED);
      assertThat(rest.postForEntity(base + "/ip-org-rules",
          json("{\"cidr\":\"10.250.0.0/16\",\"hidden\":true}"), JsonNode.class).getStatusCode())
          .isEqualTo(HttpStatus.CREATED);
      rest.postForEntity(base + "/ip-org-rules", json("{\"cidr\":\"10.251.0.0/16\",\"label\":\"Branch\"}"), JsonNode.class);
      rest.postForEntity(base + "/subnets", json("{\"cidr\":\"10.250.1.0/24\",\"label\":\"HQ servers\"}"), JsonNode.class);

      JsonNode ranges = rest.getForEntity(base + "/custom-private-ranges", JsonNode.class).getBody();
      JsonNode mine = find(ranges, "10.250.0.0/16");
      assertThat(mine.get("scope").asText()).isEqualTo("network");
      assertThat(mine.get("classification").asText()).isEqualTo("PUBLIC");
      assertThat(mine.get("overridesDefault").asBoolean()).isTrue();

      JsonNode org = rest.getForEntity(base + "/ip-org-rules", JsonNode.class).getBody();
      assertThat(find(org, "10.250.0.0/16").get("hidden").asBoolean()).isTrue();
      assertThat(find(org, "10.251.0.0/16").get("label").asText()).isEqualTo("Branch");

      JsonNode effective = rest.getForEntity("/api/v1/subnets?networkId=" + net, JsonNode.class).getBody();
      assertThat(find(effective, "10.250.1.0/24").get("label").asText()).isEqualTo("HQ servers");
      // The default is untouched.
      JsonNode defaults = rest.getForEntity("/api/v1/subnets", JsonNode.class).getBody();
      assertThat(find(defaults, "10.250.1.0/24").get("label").asText()).isEqualTo("Servers");
      assertThat(find(rest.getForEntity("/api/v1/ip-org-rules", JsonNode.class).getBody(), "10.251.0.0/16")).isNull();

      // Audited.
      JsonNode log = rest.getForEntity("/api/v1/audit-log?pageSize=10&search=" + net, JsonNode.class).getBody();
      assertThat(log.get("total").asLong()).isEqualTo(4);

      // A hide needs something to hide.
      assertThat(rest.postForEntity(base + "/custom-private-ranges",
          json("{\"cidr\":\"10.99.0.0/16\",\"hidden\":true}"), JsonNode.class).getStatusCode())
          .isEqualTo(HttpStatus.BAD_REQUEST);

      // Revert: the default's value applies again.
      rest.delete(base + "/custom-private-ranges/" + mine.get("id").asLong());
      JsonNode reverted = find(rest.getForEntity(base + "/custom-private-ranges", JsonNode.class).getBody(), "10.250.0.0/16");
      assertThat(reverted.get("scope").asText()).isEqualTo("default");
      assertThat(reverted.get("classification").asText()).isEqualTo("PRIVATE");

      // Default edits (#915 phase 4c) are audited, set-by-CIDR, and gated by ADDRESS_DEFAULTS.
      assertThat(jdbc.queryForObject(
              "SELECT count(*) FROM audit_log WHERE action = 'private-range.default.set' AND target_id = '10.250.0.0/16'",
              Integer.class))
          .isEqualTo(1);
      JsonNode reset = rest.postForEntity("/api/v1/custom-private-ranges",
          json("{\"cidr\":\"10.250.0.0/16\",\"classification\":\"PUBLIC\"}"), JsonNode.class).getBody();
      assertThat(reset.get("id").asLong()).isEqualTo(rangeId); // updated, not duplicated
      jdbc.update("INSERT INTO permissions (action, level, updated_by) VALUES ('ADDRESS_DEFAULTS', 'ADMIN', 'itest')");
      try {
        assertThat(rest.postForEntity("/api/v1/ip-org-rules",
            json("{\"cidr\":\"10.252.0.0/16\",\"label\":\"X\"}"), JsonNode.class).getStatusCode())
            .isEqualTo(HttpStatus.FORBIDDEN);
      } finally {
        jdbc.update("DELETE FROM permissions WHERE action = 'ADDRESS_DEFAULTS'");
      }
    } finally {
      rest.delete("/api/v1/monitor/networks/" + net);
      rest.delete("/api/v1/custom-private-ranges/" + rangeId);
      rest.delete("/api/v1/ip-org-rules/" + orgId);
      rest.delete("/api/v1/subnets/" + subnetId);
    }
  }

  /**
   * Subnet staleness baselines are per network (#915 phase 4a): confirming a label while viewing
   * network A baselines it in A only; B has none until it's confirmed (or dismissed) there.
   */
  @Test
  void subnetBaselines_arePerNetwork() throws Exception {
    ResponseEntity<JsonNode> upload = uploadFixture("identity-cases.pcap");
    String fileId =
        upload.getStatusCode() == HttpStatus.CREATED
            ? upload.getBody().get("fileId").asText()
            : upload.getBody().get("existingFileId").asText();
    assertThat(awaitAnalysis(fileId)).isEqualTo("completed");
    String a = rest.postForEntity("/api/v1/monitor/networks", json("{\"name\":\"baseline-a\"}"), JsonNode.class).getBody().get("id").asText();
    String b = rest.postForEntity("/api/v1/monitor/networks", json("{\"name\":\"baseline-b\"}"), JsonNode.class).getBody().get("id").asText();
    Long subnetId = null;
    try {
      for (String n : java.util.List.of(a, b)) {
        assertThat(rest.postForEntity("/api/v1/monitor/networks/" + n + "/snapshots",
            json("{\"fileId\":\"" + fileId + "\"}"), JsonNode.class).getStatusCode().is2xxSuccessful()).isTrue();
      }
      JsonNode saved = rest.postForEntity("/api/v1/subnets",
          json("{\"cidr\":\"10.0.0.0/24\",\"label\":\"Office\",\"confirmed\":true,\"networkId\":\"" + a + "\"}"),
          JsonNode.class).getBody();
      subnetId = saved.get("id").asLong();
      assertThat(saved.get("labeledAt").isNull()).isFalse();

      JsonNode inA = find(rest.getForEntity("/api/v1/subnets?networkId=" + a, JsonNode.class).getBody(), "10.0.0.0/24");
      JsonNode inB = find(rest.getForEntity("/api/v1/subnets?networkId=" + b, JsonNode.class).getBody(), "10.0.0.0/24");
      assertThat(inA.get("labeledAt").isNull()).isFalse();
      assertThat(inB.get("labeledAt").isNull()).isTrue();

      rest.postForEntity("/api/v1/subnets/" + subnetId + "/dismiss-staleness?networkId=" + b, null, JsonNode.class);
      inB = find(rest.getForEntity("/api/v1/subnets?networkId=" + b, JsonNode.class).getBody(), "10.0.0.0/24");
      assertThat(inB.get("labeledAt").isNull()).isFalse();
      assertThat(jdbc.queryForObject("SELECT count(*) FROM subnet_network_baselines WHERE subnet_id = ?", Integer.class, subnetId))
          .isEqualTo(2);
    } finally {
      rest.delete("/api/v1/monitor/networks/" + a);
      rest.delete("/api/v1/monitor/networks/" + b);
      if (subnetId != null) rest.delete("/api/v1/subnets/" + subnetId);
    }
  }

  private static JsonNode find(JsonNode list, String cidr) {
    for (JsonNode n : list) if (cidr.equals(n.path("cidr").asText())) return n;
    return null;
  }

  /**
   * Permissions and the audit log with login off (#915): everyone is an analyst and no one is an
   * admin (SYSTEM_SETTINGS_EDITABLE defaults to false). Analyst actions work and are audited as
   * "system"; admin actions and changing permission levels are refused with the reason.
   */
  @Test
  void permissionsAndAudit_loginOff() {
    jdbc.update("DELETE FROM permissions"); // tests share the DB

    JsonNode me = rest.getForEntity("/api/v1/me", JsonNode.class).getBody();
    assertThat(me.get("authEnabled").asBoolean()).isFalse();
    assertThat(me.get("admin").asBoolean()).isFalse();
    assertThat(me.get("username").asText()).isEqualTo("system");
    assertThat(me.get("canManagePermissions").asBoolean()).isFalse();
    java.util.Map<String, JsonNode> perms = new java.util.HashMap<>();
    me.get("permissions").forEach(p -> perms.put(p.get("action").asText(), p));
    assertThat(perms.get("NETWORK_SETTINGS").get("allowed").asBoolean()).isTrue();
    assertThat(perms.get("RETENTION").get("allowed").asBoolean()).isFalse();
    assertThat(perms.get("RETENTION").get("reason").asText()).contains("SYSTEM_SETTINGS_EDITABLE");

    String id =
        rest.postForEntity("/api/v1/monitor/networks", json("{\"name\":\"audit-net\"}"), JsonNode.class)
            .getBody()
            .get("id")
            .asText();
    ResponseEntity<JsonNode> saved =
        rest.exchange(
            "/api/v1/monitor/networks/" + id + "/settings",
            HttpMethod.PUT,
            json("{\"inactivityMode\":\"DAYS\",\"inactivityThreshold\":7}"),
            JsonNode.class);
    assertThat(saved.getStatusCode()).isEqualTo(HttpStatus.OK);

    JsonNode log =
        rest.getForEntity("/api/v1/audit-log?pageSize=5&search=" + id, JsonNode.class).getBody();
    assertThat(log.get("total").asLong()).isEqualTo(1);
    JsonNode entry = log.get("data").get(0);
    assertThat(entry.get("actor").asText()).isEqualTo("system");
    assertThat(entry.get("action").asText()).isEqualTo("network.settings.update");
    assertThat(entry.path("before").path("inactivityMode").asText()).isEqualTo("SNAPSHOTS");
    assertThat(entry.path("after").path("inactivityThreshold").asInt()).isEqualTo(7);

    ResponseEntity<JsonNode> change =
        rest.exchange(
            "/api/v1/permissions/NETWORK_SETTINGS", HttpMethod.PUT, json("{\"level\":\"ADMIN\"}"), JsonNode.class);
    assertThat(change.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

    // An admin could raise it (simulated here); then the same analyst save is refused, unaudited.
    jdbc.update(
        "INSERT INTO permissions (action, level, updated_by) VALUES ('NETWORK_SETTINGS', 'ADMIN', 'itest')");
    ResponseEntity<JsonNode> refused =
        rest.exchange(
            "/api/v1/monitor/networks/" + id + "/settings",
            HttpMethod.PUT,
            json("{\"inactivityMode\":\"SNAPSHOTS\",\"inactivityThreshold\":2}"),
            JsonNode.class);
    assertThat(refused.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    assertThat(refused.getBody().get("message").asText()).contains("only admins");
    assertThat(
            rest.getForEntity("/api/v1/audit-log?search=" + id, JsonNode.class)
                .getBody()
                .get("total")
                .asLong())
        .isEqualTo(1);

    jdbc.update("DELETE FROM permissions");
    rest.exchange("/api/v1/monitor/networks/" + id, HttpMethod.DELETE, null, Void.class);
  }

  /**
   * Editable analysis policy with login off (#915 phase 5). Detection thresholds are analyst-level
   * by default, so they can be changed, and are audited; retention is admin-level, so it can't.
   * Setting the deployment's value again, or resetting, removes the override.
   */
  @Test
  void editablePolicy_loginOff_thresholdsYes_retentionNo() {
    jdbc.update("DELETE FROM permissions");
    jdbc.update("DELETE FROM system_settings");
    String url = "/api/v1/system/settings/HTTP_MIN_REQUESTS";

    ResponseEntity<JsonNode> set = rest.exchange(url, HttpMethod.PUT, json("{\"value\":\"35\"}"), JsonNode.class);
    assertThat(set.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(set.getBody().get("value").asText()).isEqualTo("35");
    assertThat(set.getBody().get("overridden").asBoolean()).isTrue();
    assertThat(set.getBody().get("deployValue").asText()).isEqualTo("20");
    assertThat(set.getBody().get("editable").asBoolean()).isTrue();

    JsonNode log =
        rest.getForEntity("/api/v1/audit-log?search=HTTP_MIN_REQUESTS", JsonNode.class).getBody();
    assertThat(log.get("total").asLong()).isGreaterThanOrEqualTo(1);
    assertThat(log.get("data").get(0).path("after").path("value").asText()).isEqualTo("35");

    ResponseEntity<JsonNode> bad = rest.exchange(url, HttpMethod.PUT, json("{\"value\":\"1.5\"}"), JsonNode.class);
    assertThat(bad.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

    ResponseEntity<JsonNode> retention =
        rest.exchange(
            "/api/v1/system/settings/FILE_RETENTION_HOURS", HttpMethod.PUT, json("{\"value\":\"48\"}"), JsonNode.class);
    assertThat(retention.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

    ResponseEntity<JsonNode> deployTime =
        rest.exchange(
            "/api/v1/system/settings/SURICATA_ENABLED", HttpMethod.PUT, json("{\"value\":\"false\"}"), JsonNode.class);
    assertThat(deployTime.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);

    java.util.Map<String, JsonNode> byKey = new java.util.HashMap<>();
    rest.getForEntity("/api/v1/system/settings", JsonNode.class).getBody().forEach(n -> byKey.put(n.get("key").asText(), n));
    assertThat(byKey.get("FILE_RETENTION_HOURS").get("inAppEditable").asBoolean()).isTrue();
    assertThat(byKey.get("FILE_RETENTION_HOURS").get("editable").asBoolean()).isFalse();
    assertThat(byKey.get("FILE_RETENTION_HOURS").get("lockedReason").asText()).contains("SYSTEM_SETTINGS_EDITABLE");
    assertThat(byKey.get("SURICATA_ENABLED").get("inAppEditable").asBoolean()).isFalse();

    assertThat(rest.exchange(url, HttpMethod.DELETE, null, Void.class).getStatusCode())
        .isEqualTo(HttpStatus.NO_CONTENT);
    JsonNode after = rest.getForEntity("/api/v1/system/settings", JsonNode.class).getBody();
    after.forEach(
        n -> {
          if (n.get("key").asText().equals("HTTP_MIN_REQUESTS")) {
            assertThat(n.get("value").asText()).isEqualTo("20");
            assertThat(n.get("overridden").asBoolean()).isFalse();
          }
        });
  }

  /**
   * Detection rules in the database (#925 phase 1): CRUD, export and import through the API, and
   * the analysis applies an enabled global rule (and ignores a disabled one) to a fresh capture.
   */
  @Test
  void detectionRules_crudExportImport_andAnalysisUsesThem() throws Exception {
    jdbc.update("DELETE FROM permissions");
    String tag = "itest-" + java.util.UUID.randomUUID().toString().substring(0, 8);
    String ruleJson =
        "{\"name\":\"" + tag + "-port\",\"severity\":\"high\",\"match\":{\"dstPort\":5999,\"protocol\":\"UDP\"},"
            + "\"payloadContains\":[{\"ascii\":\"" + tag + "\"}]}";

    ResponseEntity<JsonNode> created = rest.postForEntity("/api/v1/detection-rules", json(ruleJson), JsonNode.class);
    assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    String id = created.getBody().get("id").asText();
    assertThat(created.getBody().get("version").asInt()).isEqualTo(1);
    assertThat(created.getBody().get("createdBy").asText()).isEqualTo("system");

    ResponseEntity<JsonNode> dup = rest.postForEntity("/api/v1/detection-rules", json(ruleJson), JsonNode.class);
    assertThat(dup.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(dup.getBody().path("validationErrors").has("name")).isTrue();

    ResponseEntity<JsonNode> invalid =
        rest.postForEntity(
            "/api/v1/detection-rules",
            json("{\"name\":\"" + tag + "-bad\",\"severity\":\"low\",\"payloadRegex\":[{\"pattern\":\"(\"}]}"),
            JsonNode.class);
    assertThat(invalid.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(invalid.getBody().path("validationErrors").has("payloadRegex[0].pattern")).isTrue();

    // A disabled rule that would also match: it must not fire.
    rest.postForEntity(
        "/api/v1/detection-rules",
        json("{\"name\":\"" + tag + "-off\",\"severity\":\"low\",\"enabled\":false,\"match\":{\"dstPort\":5999}}"),
        JsonNode.class);

    // Analysis applies the enabled rule to a capture nobody has uploaded before.
    ResponseEntity<JsonNode> upload = uploadBytes(tag + ".pcap", udpPcap(tag));
    assertThat(upload.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    String fileId = upload.getBody().get("fileId").asText();
    assertThat(awaitAnalysis(fileId)).isEqualTo("completed");
    JsonNode sigs = rest.getForEntity("/api/v1/conversations/" + fileId + "/custom-signatures", JsonNode.class).getBody();
    java.util.List<String> names = new java.util.ArrayList<>();
    sigs.forEach(n -> names.add(n.asText()));
    assertThat(names).contains(tag + "-port").doesNotContain(tag + "-off");

    // Edit bumps the version and is audited.
    ResponseEntity<JsonNode> edited =
        rest.exchange(
            "/api/v1/detection-rules/" + id,
            HttpMethod.PUT,
            json(ruleJson.replace("\"high\"", "\"critical\"")),
            JsonNode.class);
    assertThat(edited.getBody().get("version").asInt()).isEqualTo(2);
    JsonNode audit = rest.getForEntity("/api/v1/audit-log?search=" + id, JsonNode.class).getBody();
    assertThat(audit.get("total").asLong()).isEqualTo(2); // create + update

    // Export, delete, import back.
    ResponseEntity<String> export = rest.getForEntity("/api/v1/detection-rules/export", String.class);
    assertThat(export.getHeaders().getContentDisposition().getFilename()).isEqualTo("tracepcap-detection-rules.yml");
    assertThat(export.getBody()).contains(tag + "-port").contains("severity: critical").contains("enabled: false");
    assertThat(rest.exchange("/api/v1/detection-rules/" + id, HttpMethod.DELETE, null, Void.class).getStatusCode())
        .isEqualTo(HttpStatus.NO_CONTENT);
    com.fasterxml.jackson.databind.node.ObjectNode body = new com.fasterxml.jackson.databind.ObjectMapper().createObjectNode();
    body.put("content", export.getBody());
    body.put("mode", "MERGE");
    JsonNode imported =
        rest.postForEntity("/api/v1/detection-rules/import", json(body.toString()), JsonNode.class).getBody();
    assertThat(imported.get("created").asInt()).isGreaterThanOrEqualTo(1);
    JsonNode list = rest.getForEntity("/api/v1/detection-rules", JsonNode.class).getBody();
    java.util.Map<String, JsonNode> byName = new java.util.HashMap<>();
    list.forEach(n -> byName.put(n.get("name").asText(), n));
    assertThat(byName.get(tag + "-port").get("severity").asText()).isEqualTo("critical");
    assertThat(byName.get(tag + "-off").get("enabled").asBoolean()).isFalse();

    jdbc.update("DELETE FROM detection_rules WHERE name LIKE ?", tag + "%");
  }

  /**
   * The one-time upgrade import of the old signatures.yml (#925, Flyway V51): valid rules arrive
   * enabled, invalid ones disabled with the reason, nameless and repeated ones are skipped, and one
   * audit entry records it.
   */
  @Test
  void legacySignaturesFile_isImportedOnce_invalidRulesDisabledNotLost() throws Exception {
    String tag = "legacy-" + java.util.UUID.randomUUID().toString().substring(0, 8);
    java.nio.file.Path file = java.nio.file.Files.createTempFile("signatures", ".yml");
    java.nio.file.Files.writeString(
        file,
        "signatures:\n"
            + "  - name: " + tag + "-ok\n    severity: high\n    match: {cidr: 198.51.100.0/24}\n"
            + "    device_type: CCTV Camera\n"
            + "  - name: " + tag + "-badregex\n    payload_regex: [{pattern: '('}]\n"
            + "  - name: " + tag + "-ok\n    match: {app: TOR}\n"
            + "  - match: {ip: 1.2.3.4}\n");
    try (java.sql.Connection c = jdbc.getDataSource().getConnection()) {
      var result = db.migration.V51__import_signatures_yml.importFile(c, file);
      assertThat(result.imported()).isEqualTo(2);
      assertThat(result.disabled()).containsExactly(tag + "-badregex");
      assertThat(result.skipped()).hasSize(2);
    } finally {
      java.nio.file.Files.deleteIfExists(file);
    }
    var rows =
        jdbc.queryForList("SELECT name, enabled, device_type, description FROM detection_rules WHERE name LIKE ?", tag + "%");
    java.util.Map<String, java.util.Map<String, Object>> byName = new java.util.HashMap<>();
    rows.forEach(r -> byName.put((String) r.get("name"), r));
    assertThat(byName.get(tag + "-ok").get("enabled")).isEqualTo(true);
    assertThat(byName.get(tag + "-ok").get("device_type")).isEqualTo("CCTV Camera");
    assertThat(byName.get(tag + "-badregex").get("enabled")).isEqualTo(false);
    assertThat((String) byName.get(tag + "-badregex").get("description")).contains("Imported disabled");
    assertThat(
            jdbc.queryForObject(
                "SELECT count(*) FROM audit_log WHERE action = 'detection-rules.import' AND after_value::text LIKE ?",
                Long.class,
                "%" + file.getFileName() + "%"))
        .isEqualTo(1);
    jdbc.update("DELETE FROM detection_rules WHERE name LIKE ?", tag + "%");
  }

  /**
   * Rule sync (#925 phase 2): analysis records what it checked, a rule edit makes the capture
   * stale, Re-apply brings it up to date, switching a rule off / renaming / deleting relabels at
   * once, and a payload rule on a capture whose packets were pruned is "couldn't re-check".
   */
  @Test
  void ruleSync_staleAfterEdit_reapplyFixes_labelsFollowRuleChanges() throws Exception {
    jdbc.update("DELETE FROM permissions");
    String tag = "sync-" + java.util.UUID.randomUUID().toString().substring(0, 8);
    String r1 = createRule("{\"name\":\"" + tag + "-a\",\"severity\":\"high\",\"match\":{\"dstPort\":5999},"
        + "\"payloadContains\":[{\"ascii\":\"" + tag + "\"}]}");

    String fileId = uploadBytes(tag + ".pcap", udpPcap(tag)).getBody().get("fileId").asText();
    assertThat(awaitAnalysis(fileId)).isEqualTo("completed");
    assertThat(labels(fileId)).containsExactly(tag + "-a");
    assertThat(ruleStatus(fileId).get("staleRules")).isEmpty();

    // Editing what a rule matches leaves the old matches shown, but marks the capture stale.
    putRule(r1, "{\"name\":\"" + tag + "-a\",\"severity\":\"critical\",\"match\":{\"dstPort\":5999},"
        + "\"payloadContains\":[{\"ascii\":\"" + tag + "\"}]}");
    String r2 = createRule("{\"name\":\"" + tag + "-b\",\"severity\":\"low\",\"match\":{\"protocol\":\"UDP\",\"dstPort\":5999}}");
    JsonNode stale = ruleStatus(fileId);
    assertThat(stale.get("staleRules").toString()).contains(tag + "-a").contains(tag + "-b");
    assertThat(labels(fileId)).containsExactly(tag + "-a");
    assertThat(rest.getForEntity("/api/v1/detection-rules/status", JsonNode.class).getBody().get("staleCaptures").asInt())
        .isGreaterThanOrEqualTo(1);

    // Re-apply to this capture.
    ResponseEntity<JsonNode> job =
        rest.postForEntity("/api/v1/rule-reapply-jobs", json("{\"fileId\":\"" + fileId + "\"}"), JsonNode.class);
    assertThat(job.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    assertThat(awaitJob(job.getBody().get("id").asText()).get("status").asText()).isEqualTo("DONE");
    assertThat(ruleStatus(fileId).get("staleRules")).isEmpty();
    assertThat(labels(fileId)).containsExactlyInAnyOrder(tag + "-a", tag + "-b");

    // Switching a rule off hides its matches at once; on brings them back.
    putRule(r2, "{\"name\":\"" + tag + "-b\",\"severity\":\"low\",\"enabled\":false,\"match\":{\"protocol\":\"UDP\",\"dstPort\":5999}}");
    assertThat(labels(fileId)).containsExactly(tag + "-a");
    // Renaming relabels at once (and, being an edit, makes it stale again).
    putRule(r1, "{\"name\":\"" + tag + "-renamed\",\"severity\":\"critical\",\"match\":{\"dstPort\":5999},"
        + "\"payloadContains\":[{\"ascii\":\"" + tag + "\"}]}");
    assertThat(labels(fileId)).containsExactly(tag + "-renamed");

    // Retention deleted the packets: the payload rule can't be re-checked, so its match is dropped.
    jdbc.update("UPDATE files SET packets_pruned_at = now() WHERE id = ?::uuid", fileId);
    awaitJob(
        rest.postForEntity("/api/v1/rule-reapply-jobs", json("{\"fileId\":\"" + fileId + "\"}"), JsonNode.class)
            .getBody().get("id").asText());
    JsonNode afterPrune = ruleStatus(fileId);
    assertThat(afterPrune.get("staleRules")).isEmpty();
    assertThat(afterPrune.get("uncheckableRules").toString()).contains(tag + "-renamed");
    assertThat(labels(fileId)).isEmpty();

    // Deleting a rule removes its matches and its label.
    putRule(r2, "{\"name\":\"" + tag + "-b\",\"severity\":\"low\",\"enabled\":true,\"match\":{\"protocol\":\"UDP\",\"dstPort\":5999}}");
    assertThat(labels(fileId)).containsExactly(tag + "-b");
    rest.exchange("/api/v1/detection-rules/" + r2, HttpMethod.DELETE, null, Void.class);
    assertThat(labels(fileId)).isEmpty();
    assertThat(jdbc.queryForObject("SELECT count(*) FROM rule_matches WHERE file_id = ?::uuid", Long.class, fileId)).isZero();

    jdbc.update("DELETE FROM detection_rules WHERE name LIKE ?", tag + "%");
  }

  /**
   * Capture rules (#925 phase 3): they label only their own capture, at once; their names can't
   * clash with global rules; promoting one makes a linked global copy that keeps the source
   * capture's label even when the original goes; and their permission is enforced.
   */
  @Test
  void captureRules_applyAtOnceToTheirCaptureOnly_andPromote() throws Exception {
    jdbc.update("DELETE FROM permissions");
    String tag = "cap-" + java.util.UUID.randomUUID().toString().substring(0, 8);
    String a = uploadBytes(tag + "-a.pcap", udpPcap(tag + "-a")).getBody().get("fileId").asText();
    String b = uploadBytes(tag + "-b.pcap", udpPcap(tag + "-b")).getBody().get("fileId").asText();
    assertThat(awaitAnalysis(a)).isEqualTo("completed");
    assertThat(awaitAnalysis(b)).isEqualTo("completed");

    String rule = "{\"name\":\"" + tag + "\",\"severity\":\"high\",\"match\":{\"dstPort\":5999}}";
    ResponseEntity<JsonNode> created =
        rest.postForEntity("/api/v1/files/" + a + "/detection-rules", json(rule), JsonNode.class);
    assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    assertThat(created.getBody().get("scope").asText()).isEqualTo("CAPTURE");
    String id = created.getBody().get("id").asText();
    assertThat(labels(a)).containsExactly(tag); // checked at once, no Re-apply
    assertThat(labels(b)).doesNotContain(tag);
    assertThat(ruleStatus(a).get("staleRules")).isEmpty();

    // A global rule can't take the same name: both would label capture a.
    ResponseEntity<JsonNode> clash = rest.postForEntity("/api/v1/detection-rules", json(rule), JsonNode.class);
    assertThat(clash.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    assertThat(clash.getBody().path("validationErrors").path("name").asText()).contains("capture");

    JsonNode forA = rest.getForEntity("/api/v1/detection-rules?fileId=" + a, JsonNode.class).getBody();
    assertThat(forA.toString()).contains("\"scope\":\"CAPTURE\"").contains(tag);
    JsonNode globalOnly = rest.getForEntity("/api/v1/detection-rules", JsonNode.class).getBody();
    assertThat(globalOnly.toString()).doesNotContain(tag);

    // Promote, removing the original: the global copy keeps a's label at once; b is now stale.
    ResponseEntity<JsonNode> promoted =
        rest.postForEntity("/api/v1/detection-rules/" + id + "/promotions", json("{\"keepOriginal\":false}"), JsonNode.class);
    assertThat(promoted.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    assertThat(promoted.getBody().get("scope").asText()).isEqualTo("GLOBAL");
    assertThat(promoted.getBody().get("promotedFrom").asText()).isEqualTo(id);
    assertThat(rest.getForEntity("/api/v1/detection-rules/" + id, JsonNode.class).getStatusCode())
        .isEqualTo(HttpStatus.NOT_FOUND);
    assertThat(labels(a)).containsExactly(tag);
    assertThat(ruleStatus(a).get("staleRules")).isEmpty();
    assertThat(ruleStatus(b).get("staleRules").toString()).contains(tag);

    // The capture-rule permission is enforced.
    jdbc.update("INSERT INTO permissions (action, level, updated_by) VALUES ('DETECTION_RULES_CAPTURE', 'ADMIN', 'itest')");
    assertThat(
            rest.postForEntity(
                    "/api/v1/files/" + b + "/detection-rules",
                    json(rule.replace(tag, tag + "-x")),
                    JsonNode.class)
                .getStatusCode())
        .isEqualTo(HttpStatus.FORBIDDEN);
    jdbc.update("DELETE FROM permissions");
    jdbc.update("DELETE FROM detection_rules WHERE name LIKE ?", tag + "%");
  }

  /**
   * Network rules (#925 phase 3): checked when a capture joins the network; their matches show only
   * when the capture is viewed in that network (list, filter, distinct names); switching one off
   * hides them; leaving the network drops them; names can't clash with global rules.
   */
  @Test
  void networkRules_applyWhenACaptureJoins_andShowOnlyInThatNetwork() throws Exception {
    jdbc.update("DELETE FROM permissions");
    String tag = "net-" + java.util.UUID.randomUUID().toString().substring(0, 8);
    String file = uploadBytes(tag + ".pcap", udpPcap(tag)).getBody().get("fileId").asText();
    assertThat(awaitAnalysis(file)).isEqualTo("completed");
    String net =
        rest.postForEntity("/api/v1/monitor/networks", json("{\"name\":\"" + tag + "\"}"), JsonNode.class)
            .getBody().get("id").asText();

    String rule = "{\"name\":\"" + tag + "-r\",\"severity\":\"medium\",\"match\":{\"dstPort\":5999}}";
    ResponseEntity<JsonNode> created =
        rest.postForEntity("/api/v1/monitor/networks/" + net + "/detection-rules", json(rule), JsonNode.class);
    assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    assertThat(created.getBody().get("scope").asText()).isEqualTo("NETWORK");
    String ruleId = created.getBody().get("id").asText();
    assertThat(rest.postForEntity("/api/v1/detection-rules", json(rule), JsonNode.class).getStatusCode())
        .as("a global rule can't take a network rule's name").isEqualTo(HttpStatus.BAD_REQUEST);

    // Joining the network checks its rules on the capture.
    String snap =
        rest.postForEntity("/api/v1/monitor/networks/" + net + "/snapshots", json("{\"fileId\":\"" + file + "\"}"), JsonNode.class)
            .getBody().get("id").asText();
    String inNet = "/api/v1/conversations/" + file + "?networkId=" + net;
    assertThat(rest.getForEntity(inNet, JsonNode.class).getBody().get("data").get(0).get("customSignatures").toString())
        .contains(tag + "-r");
    assertThat(labels(file)).as("not stored on the capture itself").doesNotContain(tag + "-r");
    assertThat(rest.getForEntity("/api/v1/conversations/" + file + "/custom-signatures?networkId=" + net, JsonNode.class)
            .getBody().toString()).contains(tag + "-r");
    assertThat(rest.getForEntity(inNet + "&customSignatures=" + tag + "-r", JsonNode.class).getBody().get("total").asLong())
        .isEqualTo(1);
    assertThat(rest.getForEntity("/api/v1/conversations/" + file + "?customSignatures=" + tag + "-r", JsonNode.class)
            .getBody().get("total").asLong())
        .as("outside the network the filter doesn't see it").isZero();
    assertThat(ruleStatus(file).get("staleRules")).isEmpty();

    // The snapshot's security count and the cluster view's rule filter see it too (#925 follow-ups).
    JsonNode snaps = rest.getForEntity("/api/v1/monitor/networks/" + net + "/snapshots", JsonNode.class).getBody();
    assertThat(snaps.get(0).get("securitySignalCount").asLong()).isPositive();
    String graph = "/api/v1/clusters/" + file + "/graph?groupBy=subnet24&customSignatures=" + tag + "-r";
    assertThat(rest.getForEntity(graph + "&networkId=" + net, JsonNode.class).getBody().get("clusters"))
        .as("in the network, the rule filter keeps its conversation").isNotEmpty();
    assertThat(rest.getForEntity(graph, JsonNode.class).getBody().get("clusters"))
        .as("outside it, nothing matches").isEmpty();

    // Story uses the network's rules when generated in it, and not otherwise (#925).
    java.util.UUID fileUuid = java.util.UUID.fromString(file);
    assertThat(storyFindings.detectAll(fileUuid, 1, 1, java.util.UUID.fromString(net)))
        .extracting(f -> f.getTitle()).contains("Detection rule: " + tag + "-r [" + tag + "]");
    assertThat(storyFindings.detectAll(fileUuid, 1, 1, null))
        .extracting(f -> f.getTitle()).noneMatch(t -> t.contains(tag + "-r"));

    // Switching the rule off hides its matches at once.
    rest.exchange("/api/v1/detection-rules/" + ruleId, HttpMethod.PUT,
        json(rule.replace("\"severity\"", "\"enabled\":false,\"severity\"")), JsonNode.class);
    assertThat(rest.getForEntity(inNet, JsonNode.class).getBody().get("data").get(0).get("customSignatures").toString())
        .doesNotContain(tag + "-r");

    // Leaving the network drops its results.
    rest.exchange("/api/v1/monitor/networks/" + net + "/snapshots/" + snap, HttpMethod.DELETE, null, Void.class);
    assertThat(jdbc.queryForObject("SELECT count(*) FROM rule_matches WHERE rule_id = ?::uuid", Long.class, ruleId)).isZero();
    assertThat(jdbc.queryForObject("SELECT count(*) FROM rule_evaluations WHERE rule_id = ?::uuid", Long.class, ruleId)).isZero();

    rest.exchange("/api/v1/monitor/networks/" + net, HttpMethod.DELETE, null, Void.class);
    assertThat(jdbc.queryForObject("SELECT count(*) FROM detection_rules WHERE id = ?::uuid", Long.class, ruleId))
        .as("a network's rules go with it").isZero();
  }

  /**
   * The network context for the Analysis page (#925 phase 3c): which networks a capture is in, the
   * rules that label it in one (with the network's name for the scope label), and the network's
   * matches on a single conversation's detail.
   */
  @Test
  void networkContext_listsTheCapturesNetworks_rulesWithNames_andDetailOverlay() throws Exception {
    jdbc.update("DELETE FROM permissions");
    String tag = "ctx-" + java.util.UUID.randomUUID().toString().substring(0, 8);
    String file = uploadBytes(tag + ".pcap", udpPcap(tag)).getBody().get("fileId").asText();
    assertThat(awaitAnalysis(file)).isEqualTo("completed");
    String net =
        rest.postForEntity("/api/v1/monitor/networks", json("{\"name\":\"" + tag + "-HQ\"}"), JsonNode.class)
            .getBody().get("id").asText();
    rest.postForEntity("/api/v1/monitor/networks/" + net + "/detection-rules",
        json("{\"name\":\"" + tag + "-r\",\"severity\":\"low\",\"match\":{\"dstPort\":5999}}"), JsonNode.class);
    assertThat(rest.getForEntity("/api/v1/files/" + file + "/networks", JsonNode.class).getBody()).isEmpty();
    rest.postForEntity("/api/v1/monitor/networks/" + net + "/snapshots", json("{\"fileId\":\"" + file + "\"}"), JsonNode.class);

    JsonNode nets = rest.getForEntity("/api/v1/files/" + file + "/networks", JsonNode.class).getBody();
    assertThat(nets).hasSize(1);
    assertThat(nets.get(0).get("name").asText()).isEqualTo(tag + "-HQ");

    JsonNode rules =
        rest.getForEntity("/api/v1/detection-rules?fileId=" + file + "&networkId=" + net, JsonNode.class).getBody();
    JsonNode netRule = null;
    for (JsonNode r : rules) if (r.get("name").asText().equals(tag + "-r")) netRule = r;
    assertThat(netRule).isNotNull();
    assertThat(netRule.get("scope").asText()).isEqualTo("NETWORK");
    assertThat(netRule.get("networkName").asText()).isEqualTo(tag + "-HQ");

    String convId =
        rest.getForEntity("/api/v1/conversations/" + file, JsonNode.class).getBody().get("data").get(0).get("conversationId").asText();
    assertThat(rest.getForEntity("/api/v1/conversations/detail/" + convId + "?networkId=" + net, JsonNode.class)
            .getBody().get("customSignatures").toString()).contains(tag + "-r");
    assertThat(rest.getForEntity("/api/v1/conversations/detail/" + convId, JsonNode.class)
            .getBody().get("customSignatures").toString()).doesNotContain(tag + "-r");

    // Another network the capture isn't in: its rules are checked on demand when viewed in it.
    String other =
        rest.postForEntity("/api/v1/monitor/networks", json("{\"name\":\"" + tag + "-branch\"}"), JsonNode.class)
            .getBody().get("id").asText();
    rest.postForEntity("/api/v1/monitor/networks/" + other + "/detection-rules",
        json("{\"name\":\"" + tag + "-o\",\"severity\":\"low\",\"match\":{\"protocol\":\"UDP\"}}"), JsonNode.class);
    assertThat(rest.getForEntity("/api/v1/conversations/" + file + "?networkId=" + other, JsonNode.class)
            .getBody().get("data").get(0).get("customSignatures").toString()).contains(tag + "-o");
    assertThat(rest.getForEntity("/api/v1/files/" + file + "/networks", JsonNode.class).getBody()).hasSize(1);

    rest.exchange("/api/v1/monitor/networks/" + net, HttpMethod.DELETE, null, Void.class);
    rest.exchange("/api/v1/monitor/networks/" + other, HttpMethod.DELETE, null, Void.class);
  }

  /**
   * Suppression and preview (#925 phase 4): a network switching a global rule off hides it in that
   * network's views only, and switching it back on restores it; a preview says what a rule would
   * match in a capture without saving anything.
   */
  @Test
  void suppressionHidesAGlobalRuleInOneNetwork_andPreviewMatchesWithoutSaving() throws Exception {
    jdbc.update("DELETE FROM permissions");
    String tag = "sup-" + java.util.UUID.randomUUID().toString().substring(0, 8);
    String g = createRule("{\"name\":\"" + tag + "-g\",\"severity\":\"high\",\"match\":{\"dstPort\":5999}}");
    String file = uploadBytes(tag + ".pcap", udpPcap(tag)).getBody().get("fileId").asText();
    assertThat(awaitAnalysis(file)).isEqualTo("completed");
    String net =
        rest.postForEntity("/api/v1/monitor/networks", json("{\"name\":\"" + tag + "\"}"), JsonNode.class)
            .getBody().get("id").asText();
    rest.postForEntity("/api/v1/monitor/networks/" + net + "/snapshots", json("{\"fileId\":\"" + file + "\"}"), JsonNode.class);
    String inNet = "/api/v1/conversations/" + file + "?networkId=" + net;
    java.util.function.Supplier<String> shownInNet =
        () -> rest.getForEntity(inNet, JsonNode.class).getBody().get("data").get(0).get("customSignatures").toString();
    assertThat(shownInNet.get()).contains(tag + "-g");

    String sup = "/api/v1/monitor/networks/" + net + "/detection-rules/suppressions/" + g;
    ResponseEntity<JsonNode> put = rest.exchange(sup, HttpMethod.PUT, null, JsonNode.class);
    assertThat(put.getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(put.getBody().toString()).contains(tag + "-g");
    assertThat(shownInNet.get()).doesNotContain(tag + "-g");
    assertThat(rest.getForEntity(inNet + "&customSignatures=" + tag + "-g", JsonNode.class).getBody().get("total").asLong()).isZero();
    assertThat(rest.getForEntity("/api/v1/conversations/" + file + "/custom-signatures?networkId=" + net, JsonNode.class)
            .getBody().toString()).doesNotContain(tag + "-g");
    assertThat(labels(file)).as("elsewhere it still applies").contains(tag + "-g");
    assertThat(rest.getForEntity("/api/v1/audit-log?search=" + g, JsonNode.class).getBody().toString())
        .contains("detection-rule.suppress");

    assertThat(rest.exchange(sup, HttpMethod.DELETE, null, Void.class).getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
    assertThat(shownInNet.get()).contains(tag + "-g");

    // Only a global rule can be suppressed.
    String local = rest.postForEntity("/api/v1/files/" + file + "/detection-rules",
        json("{\"name\":\"" + tag + "-c\",\"severity\":\"low\",\"match\":{\"protocol\":\"UDP\"}}"), JsonNode.class)
        .getBody().get("id").asText();
    assertThat(rest.exchange("/api/v1/monitor/networks/" + net + "/detection-rules/suppressions/" + local, HttpMethod.PUT, null, JsonNode.class)
            .getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

    // Preview: counts and samples, stores nothing.
    long rulesBefore = jdbc.queryForObject("SELECT count(*) FROM detection_rules", Long.class);
    JsonNode hit = rest.postForEntity("/api/v1/detection-rules/previews",
        json("{\"fileId\":\"" + file + "\",\"rule\":{\"name\":\"try\",\"severity\":\"low\",\"match\":{\"dstPort\":5999}}}"),
        JsonNode.class).getBody();
    assertThat(hit.get("matches").asInt()).isEqualTo(1);
    assertThat(hit.get("conversations").asInt()).isEqualTo(1);
    assertThat(hit.get("sample").get(0).get("dstPort").asInt()).isEqualTo(5999);
    JsonNode miss = rest.postForEntity("/api/v1/detection-rules/previews",
        json("{\"fileId\":\"" + file + "\",\"rule\":{\"name\":\"try\",\"severity\":\"low\",\"match\":{\"dstPort\":1}}}"),
        JsonNode.class).getBody();
    assertThat(miss.get("matches").asInt()).isZero();
    assertThat(rest.postForEntity("/api/v1/detection-rules/previews",
            json("{\"fileId\":\"" + file + "\",\"rule\":{\"name\":\"try\",\"severity\":\"low\"}}"), JsonNode.class)
        .getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    jdbc.update("UPDATE files SET packets_pruned_at = now() WHERE id = ?::uuid", file);
    JsonNode pruned = rest.postForEntity("/api/v1/detection-rules/previews",
        json("{\"fileId\":\"" + file + "\",\"rule\":{\"name\":\"try\",\"severity\":\"low\",\"payloadContains\":[{\"ascii\":\"" + tag + "\"}]}}"),
        JsonNode.class).getBody();
    assertThat(pruned.get("packetsDeleted").asBoolean()).isTrue();
    assertThat(pruned.get("matches").isNull()).isTrue();
    assertThat(jdbc.queryForObject("SELECT count(*) FROM detection_rules", Long.class)).isEqualTo(rulesBefore);

    rest.exchange("/api/v1/monitor/networks/" + net, HttpMethod.DELETE, null, Void.class);
    jdbc.update("DELETE FROM detection_rules WHERE name LIKE ?", tag + "%");
  }

  /**
   * A rule's classification hint is a weighted vote, not an override (#926): the endpoint on the
   * matched port gets it, explained in the evidence; the other endpoint doesn't.
   */
  @Test
  void ruleClassificationHint_votesForTheMatchedEndpoint_withTheRuleInTheEvidence() throws Exception {
    jdbc.update("DELETE FROM permissions");
    String tag = "hint-" + java.util.UUID.randomUUID().toString().substring(0, 8);
    createRule("{\"name\":\"" + tag + "\",\"severity\":\"low\",\"match\":{\"dstPort\":5999},"
        + "\"deviceType\":\"CCTV Camera\",\"deviceTypeWeight\":100}");
    String file = uploadBytes(tag + ".pcap", udpPcap(tag)).getBody().get("fileId").asText();
    assertThat(awaitAnalysis(file)).isEqualTo("completed");

    JsonNode hosts = rest.getForEntity("/api/v1/files/" + file + "/host-classifications", JsonNode.class).getBody();
    java.util.Map<String, JsonNode> byIp = new java.util.HashMap<>();
    hosts.forEach(h -> byIp.put(h.get("ip").asText(), h));
    JsonNode camera = byIp.get("10.99.0.2");
    assertThat(camera.get("deviceType").asText()).isEqualTo("CCTV Camera");
    // The evidence behind the verdict names the rule ("Evidence weighed").
    assertThat(rest.getForEntity("/api/v1/files/" + file + "/host-identities?ips=10.99.0.2", JsonNode.class)
            .getBody().toString()).contains("Custom rule").contains(tag);
    assertThat(camera.get("confidence").asInt()).as("a vote, not a forced 100").isLessThanOrEqualTo(100);
    assertThat(byIp.get("10.99.0.1").get("deviceType").asText())
        .as("the client on the other end isn't voted a camera").isNotEqualTo("CCTV Camera");

    // Re-apply re-scores the vote (#925): the rule now says PLC, and the machine verdict follows,
    // with the change recorded on the host, in the job's result, and in the audit log.
    String ruleId = jdbc.queryForObject("SELECT id::text FROM detection_rules WHERE name = ?", String.class, tag);
    String plc = "{\"name\":\"" + tag + "\",\"severity\":\"low\",\"match\":{\"dstPort\":5999},"
        + "\"deviceType\":\"PLC\",\"deviceTypeWeight\":100}";
    putRule(ruleId, plc);
    assertThat(deviceType(file, "10.99.0.2")).as("nothing changes until Re-apply").isEqualTo("CCTV Camera");
    JsonNode job = awaitJob(rest.postForEntity("/api/v1/rule-reapply-jobs", json("{\"fileId\":\"" + file + "\"}"), JsonNode.class)
        .getBody().get("id").asText());
    assertThat(job.get("reclassifiedCount").asInt()).isEqualTo(1);
    assertThat(job.get("reclassified").get(0).get("ip").asText()).isEqualTo("10.99.0.2");
    assertThat(job.get("reclassified").get(0).get("from").asText()).isEqualTo("CCTV Camera");
    assertThat(job.get("reclassified").get(0).get("to").asText()).isEqualTo("PLC");
    assertThat(deviceType(file, "10.99.0.2")).isEqualTo("PLC");
    JsonNode evidence = rest.getForEntity("/api/v1/files/" + file + "/hosts/10.99.0.2/identity", JsonNode.class).getBody();
    assertThat(evidence.get("reclassified").get("from").asText()).isEqualTo("CCTV Camera");
    assertThat(evidence.get("reclassified").get("rules").asText()).isEqualTo(tag);
    assertThat(jdbc.queryForObject(
            "SELECT count(*) FROM audit_log WHERE action = 'host-classification.rescore' AND target_id = ?",
            Integer.class, file + "/10.99.0.2"))
        .isEqualTo(1);

    // An analyst's label is never changed; it's flagged stale when the evidence's answer moves away.
    String override = "/api/v1/files/" + file + "/adjudications/host-identity/10.99.0.2/override";
    rest.exchange(override, HttpMethod.PUT, json("{\"label\":\"PLC\",\"rationale\":\"site survey\"}"), JsonNode.class);
    putRule(ruleId, plc.replace("PLC", "Badge Reader"));
    JsonNode job2 = awaitJob(rest.postForEntity("/api/v1/rule-reapply-jobs", json("{\"fileId\":\"" + file + "\"}"), JsonNode.class)
        .getBody().get("id").asText());
    assertThat(job2.get("staleLabelsCount").asInt()).isEqualTo(1);
    JsonNode label = rest.getForEntity(override, JsonNode.class).getBody();
    assertThat(label.get("label").asText()).isEqualTo("PLC");
    assertThat(label.get("staleSince").isNull()).isFalse();
    assertThat(label.get("staleFields").toString()).contains(tag).contains("Badge Reader");

    // Re-affirming clears it, and re-applying with nothing changed doesn't flag it again.
    rest.exchange(override, HttpMethod.PUT, json("{\"label\":\"PLC\",\"rationale\":\"still a PLC\"}"), JsonNode.class);
    jdbc.update("UPDATE rule_evaluations SET rule_version = 0 WHERE rule_id = ?::uuid", ruleId); // force a re-check
    JsonNode job3 = awaitJob(rest.postForEntity("/api/v1/rule-reapply-jobs", json("{\"fileId\":\"" + file + "\"}"), JsonNode.class)
        .getBody().get("id").asText());
    assertThat(job3.get("reclassifiedCount").asInt()).isZero();
    assertThat(rest.getForEntity(override, JsonNode.class).getBody().get("staleSince").isNull()).isTrue();

    // Deleting the rule takes its vote with it.
    rest.exchange("/api/v1/detection-rules/" + ruleId, HttpMethod.DELETE, null, Void.class);
    assertThat(deviceType(file, "10.99.0.2")).isNotEqualTo("Badge Reader");

    jdbc.update("DELETE FROM detection_rules WHERE name LIKE ?", tag + "%");
  }

  private String deviceType(String file, String ip) {
    for (JsonNode h : rest.getForEntity("/api/v1/files/" + file + "/host-classifications", JsonNode.class).getBody()) {
      if (ip.equals(h.get("ip").asText())) return h.get("deviceType").asText();
    }
    return null;
  }

  /**
   * Host identity checks from the #918 audit, items 1c and 2, on identity-cases.pcap: every TTL is
   * kept; a VRRP virtual address is marked as one (not classified as a device); cloned VMs and a
   * reused DHCP address are flagged as possibly more than one machine.
   */
  @Test
  void hostIdentity_keepsEveryTtl_marksVrrpVip_flagsPossiblyTwoMachines() throws Exception {
    ResponseEntity<JsonNode> upload = uploadFixture("identity-cases.pcap");
    String fileId =
        upload.getStatusCode() == HttpStatus.CREATED
            ? upload.getBody().get("fileId").asText()
            : upload.getBody().get("existingFileId").asText();
    assertThat(awaitAnalysis(fileId)).isEqualTo("completed");
    JsonNode hosts = rest.getForEntity("/api/v1/files/" + fileId + "/host-classifications", JsonNode.class).getBody();
    java.util.Map<String, JsonNode> byIp = new java.util.HashMap<>();
    hosts.forEach(h -> byIp.put(h.get("ip").asText(), h));

    // Cloned VMs: one IP+MAC, TTL 64 and 128, two DHCP hostnames.
    JsonNode clone = byIp.get("10.0.0.70");
    assertThat(clone.get("ttls").toString()).contains("64").contains("128");
    assertThat(clone.get("identityWarning").asText())
        .contains("Possibly more than one machine").contains("web-vm-a").contains("web-vm-b");

    // DHCP reuse: the laptop then the phone on one address. That's a timeline now (#918 item 3),
    // not a warning.
    JsonNode reused = byIp.get("10.0.0.50").path("identityWarning");
    assertThat(reused.isNull() || reused.isMissingNode()).isTrue();

    // The VRRP virtual address isn't a device.
    JsonNode vip = byIp.get("10.0.0.254");
    assertThat(vip.get("addressKind").asText()).isEqualTo("VIRTUAL_FAILOVER");
    assertThat(vip.get("deviceType").asText()).isEqualTo("VIRTUAL_ADDRESS");
    // The routers advertise from the virtual MAC, but they're the members, not the virtual address.
    for (String router : java.util.List.of("10.0.0.2", "10.0.0.3")) {
      assertThat(byIp.get(router).path("addressKind").isNull()).as(router).isTrue();
      assertThat(byIp.get(router).get("deviceType").asText()).as(router).isNotEqualTo("VIRTUAL_ADDRESS");
    }
    // The host's evidence panel carries the warning and every TTL too.
    JsonNode evidence =
        rest.getForEntity("/api/v1/files/" + fileId + "/hosts/10.0.0.70/identity", JsonNode.class).getBody();
    assertThat(evidence.get("identityWarning").asText()).contains("Possibly more than one machine");
    assertThat(evidence.get("ttls").toString()).contains("64").contains("128");

    // An ordinary host has no warning.
    assertThat(byIp.get("10.0.0.1").path("identityWarning").isNull()).isTrue();
  }

  /**
   * Re-analysis as a new version (#915 phase 3): its own copy and analysis with the new options,
   * linked to the original, with the capture's own rules; uploads still dedupe to the original; a
   * version of a version derives from the original; deleting the original leaves its versions.
   */
  @Test
  void reanalysis_createsAVersion_keepsTheOriginal_andCarriesCaptureRules() throws Exception {
    jdbc.update("DELETE FROM permissions");
    String tag = "ver-" + java.util.UUID.randomUUID().toString().substring(0, 8);
    byte[] pcap = udpPcap(tag);
    String orig = uploadBytes(tag + ".pcap", pcap).getBody().get("fileId").asText();
    assertThat(awaitAnalysis(orig)).isEqualTo("completed");
    rest.postForEntity("/api/v1/files/" + orig + "/detection-rules",
        json("{\"name\":\"" + tag + "-c\",\"severity\":\"low\",\"match\":{\"dstPort\":5999}}"), JsonNode.class);

    ResponseEntity<JsonNode> re = rest.postForEntity("/api/v1/files/" + orig + "/reanalyses",
        json("{\"enableNdpi\":true,\"enableSuricata\":false,\"enableFileExtraction\":false}"), JsonNode.class);
    assertThat(re.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    String v1 = re.getBody().get("fileId").asText();
    assertThat(v1).isNotEqualTo(orig);
    assertThat(awaitAnalysis(v1)).isEqualTo("completed");
    JsonNode meta = rest.getForEntity("/api/v1/files/" + v1, JsonNode.class).getBody();
    assertThat(meta.get("derivedFrom").asText()).isEqualTo(orig);
    assertThat(meta.get("version").asBoolean()).isTrue();
    assertThat(meta.get("enableNdpi").asBoolean()).isTrue();
    assertThat(labels(v1)).as("the capture's own rule came along and was applied").contains(tag + "-c");
    assertThat(labels(orig)).contains(tag + "-c");

    // Uploading the same capture again still points at the original.
    ResponseEntity<JsonNode> dup = uploadBytes(tag + ".pcap", pcap);
    assertThat(dup.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    assertThat(dup.getBody().get("existingFileId").asText()).isEqualTo(orig);

    // A version of a version derives from the original.
    String v2 = rest.postForEntity("/api/v1/files/" + v1 + "/reanalyses", json("{}"), JsonNode.class)
        .getBody().get("fileId").asText();
    assertThat(awaitAnalysis(v2)).isEqualTo("completed");
    assertThat(rest.getForEntity("/api/v1/files/" + v2, JsonNode.class).getBody().get("derivedFrom").asText()).isEqualTo(orig);
    JsonNode versions = rest.getForEntity("/api/v1/files/" + v2 + "/versions", JsonNode.class).getBody();
    java.util.List<String> ids = new java.util.ArrayList<>();
    versions.forEach(v -> ids.add(v.get("fileId").asText()));
    assertThat(ids).containsExactly(orig, v1, v2);

    // Deleting the original leaves its versions, with their own copy of the capture.
    assertThat(rest.exchange("/api/v1/files/" + orig, HttpMethod.DELETE, null, Void.class).getStatusCode().is2xxSuccessful()).isTrue();
    assertThat(rest.getForEntity("/api/v1/files/" + v1 + "/download", byte[].class).getStatusCode()).isEqualTo(HttpStatus.OK);
    assertThat(rest.getForEntity("/api/v1/files/" + v1 + "/versions", JsonNode.class).getBody()).isNotEmpty();

    rest.exchange("/api/v1/files/" + v1, HttpMethod.DELETE, null, Void.class);
    rest.exchange("/api/v1/files/" + v2, HttpMethod.DELETE, null, Void.class);
  }

  private String createRule(String body) {
    ResponseEntity<JsonNode> r = rest.postForEntity("/api/v1/detection-rules", json(body), JsonNode.class);
    assertThat(r.getStatusCode()).isEqualTo(HttpStatus.CREATED);
    return r.getBody().get("id").asText();
  }

  private void putRule(String id, String body) {
    assertThat(rest.exchange("/api/v1/detection-rules/" + id, HttpMethod.PUT, json(body), JsonNode.class).getStatusCode())
        .isEqualTo(HttpStatus.OK);
  }

  private java.util.List<String> labels(String fileId) {
    java.util.List<String> out = new java.util.ArrayList<>();
    rest.getForEntity("/api/v1/conversations/" + fileId + "/custom-signatures", JsonNode.class)
        .getBody()
        .forEach(n -> out.add(n.asText()));
    return out;
  }

  private JsonNode ruleStatus(String fileId) {
    return rest.getForEntity("/api/v1/files/" + fileId + "/rule-status", JsonNode.class).getBody();
  }

  private JsonNode awaitJob(String jobId) throws InterruptedException {
    for (int i = 0; i < 120; i++) {
      JsonNode j = rest.getForEntity("/api/v1/rule-reapply-jobs/" + jobId, JsonNode.class).getBody();
      if (!"RUNNING".equals(j.get("status").asText())) return j;
      Thread.sleep(250);
    }
    throw new AssertionError("re-apply job " + jobId + " didn't finish");
  }

  /** A one-packet pcap (UDP 10.99.0.1:40000 → 10.99.0.2:5999) whose payload is {@code payload}. */
  private static byte[] udpPcap(String payload) {
    byte[] data = payload.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    java.nio.ByteBuffer b = java.nio.ByteBuffer.allocate(24 + 16 + 14 + 20 + 8 + data.length);
    b.order(java.nio.ByteOrder.LITTLE_ENDIAN);
    b.putInt(0xa1b2c3d4).putShort((short) 2).putShort((short) 4).putInt(0).putInt(0).putInt(65535).putInt(1);
    int frame = 14 + 20 + 8 + data.length;
    b.putInt((int) (System.currentTimeMillis() / 1000)).putInt(0).putInt(frame).putInt(frame);
    b.order(java.nio.ByteOrder.BIG_ENDIAN);
    b.put(new byte[] {2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1}).putShort((short) 0x0800);
    b.put((byte) 0x45).put((byte) 0).putShort((short) (20 + 8 + data.length)).putShort((short) 1).putShort((short) 0);
    b.put((byte) 64).put((byte) 17).putShort((short) 0);
    b.put(new byte[] {10, 99, 0, 1}).put(new byte[] {10, 99, 0, 2});
    b.putShort((short) 40000).putShort((short) 5999).putShort((short) (8 + data.length)).putShort((short) 0);
    b.put(data);
    return b.array();
  }

  /** Polls a file until it leaves "processing" (or 2 minutes pass) and returns its status. */
  private String awaitAnalysis(String fileId) throws InterruptedException {
    String status = "processing";
    long deadline = System.currentTimeMillis() + 120_000;
    while ("processing".equals(status) && System.currentTimeMillis() < deadline) {
      Thread.sleep(500);
      status = rest.getForEntity("/api/v1/files/" + fileId, JsonNode.class).getBody().get("status").asText();
    }
    return status;
  }

  /**
   * Simultaneous identical uploads store one file (V44). Before the unique index, 8 parallel uploads
   * of the same capture all got 201 and became 8 rows, each analysed separately, because the hash
   * check and the insert are separate steps.
   */
  @Test
  void simultaneousIdenticalUploads_storeExactlyOneFile() throws Exception {
    byte[] bytes;
    try (InputStream in = getClass().getResourceAsStream("/fixtures/ftp.pcap")) {
      bytes = in.readAllBytes();
    }
    // Unique to this run, so it can't collide with the other tests' ftp.pcap uploads.
    byte[] unique = java.util.Arrays.copyOf(bytes, bytes.length + 16);
    System.arraycopy(
        UUID.randomUUID().toString().substring(0, 16).getBytes(), 0, unique, bytes.length, 16);

    int n = 6;
    java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(n);
    java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
    java.util.List<java.util.concurrent.Future<ResponseEntity<JsonNode>>> results = new java.util.ArrayList<>();
    for (int i = 0; i < n; i++) {
      results.add(
          pool.submit(
              () -> {
                start.await();
                return uploadBytes("race.pcap", unique);
              }));
    }
    start.countDown();

    java.util.List<String> createdIds = new java.util.ArrayList<>();
    java.util.Set<String> pointedAt = new java.util.HashSet<>();
    for (java.util.concurrent.Future<ResponseEntity<JsonNode>> f : results) {
      ResponseEntity<JsonNode> r = f.get(60, java.util.concurrent.TimeUnit.SECONDS);
      assertThat(r.getStatusCode()).isIn(HttpStatus.CREATED, HttpStatus.CONFLICT);
      if (r.getStatusCode() == HttpStatus.CREATED) createdIds.add(r.getBody().get("fileId").asText());
      else pointedAt.add(r.getBody().get("existingFileId").asText());
    }
    pool.shutdown();

    assertThat(createdIds).as("exactly one upload wins").hasSize(1);
    assertThat(pointedAt).as("every loser is pointed at the winner").containsOnly(createdIds.get(0));
    String hash =
        java.util.HexFormat.of()
            .formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(unique));
    assertThat(jdbc.queryForObject("SELECT count(*) FROM files WHERE file_hash = ?", Integer.class, hash))
        .isEqualTo(1);
  }

  /**
   * Uploads the shared fixture and returns its id.
   *
   * <p>201 on a fresh container; 409 once another test in this class has already stored the same
   * pcap, which returns the existing id instead. Tests share one container, so both are normal.
   */
  private String uploadedFileId() {
    ResponseEntity<JsonNode> upload = uploadFixture("ftp.pcap");
    JsonNode body = upload.getBody();
    assertThat(body).isNotNull();
    return upload.getStatusCode() == HttpStatus.CREATED
        ? body.get("fileId").asText()
        : body.get("existingFileId").asText();
  }
}
