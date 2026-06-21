package com.tracepcap.common.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/system")
@Tag(name = "System", description = "Server time and runtime limits")
public class SystemController {

  @Value("${MAX_UPLOAD_SIZE_BYTES:536870912}")
  private long maxUploadSizeBytes;

  @Value("${ANALYSIS_TIMEOUT_SECONDS:300}")
  private int analysisTimeoutSeconds;

  @Value("${llm.api.timeout-seconds:300}")
  private int llmTimeoutSeconds;

  /** Returns the server's current local datetime (ISO-8601, no timezone offset). */
  @GetMapping("/time")
  @Operation(summary = "Get the server's current local datetime")
  public ResponseEntity<Map<String, String>> getServerTime() {
    return ResponseEntity.ok(
        Map.of("now", LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm"))));
  }

  /**
   * Returns runtime limits derived from APP_MEMORY_MB so the frontend never needs build-time baked
   * values. Consumed by the upload page and the analysis polling hook.
   */
  @GetMapping("/limits")
  @Operation(summary = "Get runtime limits (upload size, analysis and LLM timeouts)")
  public ResponseEntity<Map<String, Object>> getLimits() {
    return ResponseEntity.ok(
        Map.of(
            "maxUploadBytes",
            maxUploadSizeBytes,
            "maxUploadMb",
            maxUploadSizeBytes / 1024 / 1024,
            "analysisTimeoutMs",
            (long) analysisTimeoutSeconds * 1000,
            "llmTimeoutMs",
            (long) llmTimeoutSeconds * 1000));
  }
}
