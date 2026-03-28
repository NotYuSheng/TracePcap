package com.tracepcap.common.controller;

import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/system")
public class SystemController {

  @Value("${MAX_UPLOAD_SIZE_BYTES:536870912}")
  private long maxUploadSizeBytes;

  @Value("${ANALYSIS_TIMEOUT_SECONDS:300}")
  private int analysisTimeoutSeconds;

  /**
   * Returns runtime limits derived from APP_MEMORY_MB so the frontend never needs build-time baked
   * values. Consumed by the upload page and the analysis polling hook.
   */
  @GetMapping("/limits")
  public ResponseEntity<Map<String, Object>> getLimits() {
    return ResponseEntity.ok(
        Map.of(
            "maxUploadBytes",
            maxUploadSizeBytes,
            "maxUploadMb",
            maxUploadSizeBytes / 1024 / 1024,
            "analysisTimeoutMs",
            (long) analysisTimeoutSeconds * 1000));
  }
}
