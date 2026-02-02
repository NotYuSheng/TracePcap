package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.AnalysisSummaryResponse;
import com.tracepcap.analysis.dto.ProtocolStatsResponse;
import com.tracepcap.analysis.entity.AnalysisResultEntity;
import com.tracepcap.analysis.service.AnalysisService;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.service.FileService;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** REST controller for PCAP analysis operations */
@Slf4j
@RestController
@RequestMapping("/api/analysis")
@RequiredArgsConstructor
public class AnalysisController {

  private final AnalysisService analysisService;
  private final FileService fileService;

  /**
   * Get analysis summary for a file Returns: - 200 OK: Analysis completed successfully (with data)
   * - 202 Accepted: Analysis still in progress (with Retry-After header) - 500 Internal Server
   * Error: Analysis failed - 404 Not Found: File or analysis not found
   */
  @GetMapping("/{fileId}/summary")
  public ResponseEntity<AnalysisSummaryResponse> getAnalysisSummary(@PathVariable UUID fileId) {
    log.info("GET /api/analysis/{}/summary", fileId);

    // Check file status first
    FileEntity file = fileService.getFileById(fileId);

    // Check analysis status
    AnalysisResultEntity analysis = analysisService.getAnalysisResultByFileId(fileId);

    if (analysis == null) {
      // No analysis yet - file is still processing
      log.info("Analysis for file {} not started yet, returning 202 Accepted", fileId);
      HttpHeaders headers = new HttpHeaders();
      headers.add("Retry-After", "2"); // Retry after 2 seconds
      return ResponseEntity.status(HttpStatus.ACCEPTED).headers(headers).build();
    }

    switch (analysis.getStatus()) {
      case PENDING:
      case IN_PROGRESS:
        log.info(
            "Analysis for file {} is {}, returning 202 Accepted", fileId, analysis.getStatus());
        HttpHeaders headers = new HttpHeaders();
        headers.add("Retry-After", "2"); // Retry after 2 seconds
        return ResponseEntity.status(HttpStatus.ACCEPTED).headers(headers).build();

      case COMPLETED:
        log.info("Analysis for file {} completed, returning 200 OK with data", fileId);
        AnalysisSummaryResponse response = analysisService.getAnalysisSummary(fileId);
        return ResponseEntity.ok(response);

      case FAILED:
        log.error("Analysis for file {} failed: {}", fileId, analysis.getErrorMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();

      default:
        log.error("Unknown analysis status for file {}: {}", fileId, analysis.getStatus());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
    }
  }

  /**
   * Get protocol statistics for a file Returns: - 200 OK: Analysis completed successfully (with
   * data) - 202 Accepted: Analysis still in progress - 500 Internal Server Error: Analysis failed -
   * 404 Not Found: File or analysis not found
   */
  @GetMapping("/{fileId}/protocols")
  public ResponseEntity<ProtocolStatsResponse> getProtocolStats(@PathVariable UUID fileId) {
    log.info("GET /api/analysis/{}/protocols", fileId);

    AnalysisResultEntity analysis = analysisService.getAnalysisResultByFileId(fileId);

    if (analysis == null || analysis.getStatus() != AnalysisResultEntity.AnalysisStatus.COMPLETED) {
      log.info("Analysis for file {} not completed yet, returning 202 Accepted", fileId);
      HttpHeaders headers = new HttpHeaders();
      headers.add("Retry-After", "2");
      return ResponseEntity.status(HttpStatus.ACCEPTED).headers(headers).build();
    }

    if (analysis.getStatus() == AnalysisResultEntity.AnalysisStatus.FAILED) {
      return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
    }

    ProtocolStatsResponse response = analysisService.getProtocolStats(fileId);
    return ResponseEntity.ok(response);
  }

  /** Trigger manual analysis for a file */
  @PostMapping("/{fileId}/analyze")
  public ResponseEntity<Void> analyzeFile(@PathVariable UUID fileId) {
    log.info("POST /api/analysis/{}/analyze", fileId);
    analysisService.analyzeFile(fileId);
    return ResponseEntity.accepted().build();
  }
}
