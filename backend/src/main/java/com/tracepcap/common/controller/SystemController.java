package com.tracepcap.common.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/system")
public class SystemController {

  @Value("${MAX_UPLOAD_SIZE_BYTES:536870912}")
  private long maxUploadSizeBytes;

  /**
   * Returns the effective upload size limit so the frontend can display it without
   * baking a value in at build time. Derived at container startup from APP_MEMORY_MB.
   */
  @GetMapping("/limits")
  public ResponseEntity<Map<String, Object>> getLimits() {
    return ResponseEntity.ok(Map.of(
        "maxUploadBytes", maxUploadSizeBytes,
        "maxUploadMb",    maxUploadSizeBytes / 1024 / 1024
    ));
  }
}
