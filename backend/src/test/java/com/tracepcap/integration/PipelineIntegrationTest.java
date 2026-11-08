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
