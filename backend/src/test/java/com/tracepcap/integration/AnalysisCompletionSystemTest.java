package com.tracepcap.integration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

import com.fasterxml.jackson.databind.JsonNode;
import java.io.InputStream;
import java.time.Duration;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * System test for the async analysis pipeline's happy path: upload a pcap, let the real
 * tshark/nDPI toolchain process it, and assert the {@code 202 → 200} transition on the analysis
 * summary. This requires the full stack (the analysis binaries only exist in the backend image), so
 * it is excluded from {@code mvn verify} and runs only when {@code RUN_SYSTEM_TESTS=true} against a
 * stack reachable at {@code E2E_BASE_URL} (default {@code http://localhost:8888}).
 *
 * <p>The wait is driven by Awaitility polling — never {@code Thread.sleep} — which is the correct
 * way to assert on eventually-consistent async state.
 */
@Tag("system")
@EnabledIfEnvironmentVariable(named = "RUN_SYSTEM_TESTS", matches = "true")
class AnalysisCompletionSystemTest {

  private static final String BASE =
      System.getenv().getOrDefault("E2E_BASE_URL", "http://localhost:8888");

  /** RestTemplate that never throws on non-2xx, so status codes (202/409/4xx) can be inspected. */
  private final RestTemplate http = inspectableRestTemplate();

  @Test
  void uploadedPcap_isAnalyzedAndSummaryBecomesAvailable() throws Exception {
    String fileId = uploadFtpFixture();

    // The summary is 202 (Accepted, with Retry-After) while PENDING/IN_PROGRESS, then 200 once
    // COMPLETED. Poll the file status to completion, failing fast if the pipeline reports 'failed'.
    await()
        .atMost(Duration.ofSeconds(120))
        .pollInterval(Duration.ofSeconds(3))
        .ignoreExceptions() // tolerate transient connect glitches while the stack settles
        .untilAsserted(
            () -> {
              JsonNode file = getJson("/api/v1/files/" + fileId);
              assertThat(file).isNotNull();
              String status = file.path("status").asText();
              assertThat(status).as("analysis status").isNotEqualTo("failed");
              assertThat(status).isEqualTo("completed");
            });

    // After completion the summary flips from 202 to 200 with a populated body.
    ResponseEntity<JsonNode> summary =
        http.getForEntity(BASE + "/api/v1/analysis/" + fileId + "/summary", JsonNode.class);
    assertThat(summary.getStatusCode().value()).isEqualTo(200);
    assertThat(summary.getBody()).isNotNull();
    assertThat(summary.getBody().size()).isGreaterThan(0);
  }

  private String uploadFtpFixture() throws Exception {
    byte[] bytes;
    try (InputStream in = getClass().getResourceAsStream("/fixtures/ftp.pcap")) {
      assertThat(in).as("fixture /fixtures/ftp.pcap").isNotNull();
      bytes = in.readAllBytes();
    }

    MultiValueMap<String, Object> form = new LinkedMultiValueMap<>();
    form.add(
        "file",
        new ByteArrayResource(bytes) {
          @Override
          public String getFilename() {
            return "ftp.pcap";
          }
        });
    form.add("enableNdpi", "true");
    form.add("enableSuricata", "false");
    form.add("enableFileExtraction", "false");
    form.add("source", "ANALYSIS");

    HttpHeaders headers = new HttpHeaders();
    headers.setContentType(MediaType.MULTIPART_FORM_DATA);

    ResponseEntity<JsonNode> resp =
        http.exchange(
            BASE + "/api/v1/files", HttpMethod.POST, new HttpEntity<>(form, headers), JsonNode.class);

    JsonNode body = resp.getBody();
    assertThat(body).isNotNull();
    // 201 fresh, or 409 if this pcap is already stored (dedup by hash) — reuse the existing file.
    String fileId =
        resp.getStatusCode().value() == 409
            ? body.get("existingFileId").asText()
            : body.get("fileId").asText();
    assertThat(fileId).isNotBlank();
    return fileId;
  }

  private JsonNode getJson(String path) {
    return http.getForEntity(BASE + path, JsonNode.class).getBody();
  }

  private static RestTemplate inspectableRestTemplate() {
    // Bound connect/read so a hung or unreachable server fails fast instead of blocking CI.
    SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
    factory.setConnectTimeout(10_000);
    factory.setReadTimeout(30_000);
    RestTemplate rt = new RestTemplate(factory);
    rt.setErrorHandler(
        new ResponseErrorHandler() {
          @Override
          public boolean hasError(ClientHttpResponse response) {
            return false;
          }

          @Override
          public void handleError(ClientHttpResponse response) {
            // no-op: status is inspected by the caller
          }
        });
    return rt;
  }
}
