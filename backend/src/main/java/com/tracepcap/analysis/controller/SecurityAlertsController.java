package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.ConversationResponse;
import com.tracepcap.analysis.service.AnalysisService;
import io.swagger.v3.oas.annotations.Operation;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** REST controller for nDPI security alerts per file. */
@Slf4j
@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
public class SecurityAlertsController {

  private final AnalysisService analysisService;

  /**
   * Returns all conversations for the given file that have at least one nDPI risk flag.
   * Returns an empty list for PCAPs with no detected risks.
   */
  @GetMapping("/{fileId}/security-alerts")
  @Operation(summary = "Get conversations with nDPI security risk flags")
  public ResponseEntity<List<ConversationResponse>> getSecurityAlerts(
      @PathVariable UUID fileId) {
    log.info("GET /api/files/{}/security-alerts", fileId);
    return ResponseEntity.ok(analysisService.getSecurityAlerts(fileId));
  }
}
