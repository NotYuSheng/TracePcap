package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.AnalysisProgressResponse;
import com.tracepcap.analysis.dto.AnalysisSummaryResponse;
import com.tracepcap.analysis.dto.ProtocolStatsResponse;
import com.tracepcap.analysis.entity.AnalysisResultEntity;
import com.tracepcap.analysis.service.AnalysisProgressService;
import com.tracepcap.analysis.service.AnalysisService;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.service.FileService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
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
@RequestMapping("/analysis")
@RequiredArgsConstructor
@Tag(name = "Analysis", description = "PCAP analysis summary and protocol statistics")
public class AnalysisController {

  private final AnalysisService analysisService;
  private final AnalysisProgressService analysisProgressService;
  private final FileService fileService;

  /**
   * Get analysis summary for a file Returns: - 200 OK: Analysis completed successfully (with data)
   * - 202 Accepted: Analysis still in progress (with Retry-After header) - 500 Internal Server
   * Error: Analysis failed - 404 Not Found: File or analysis not found
   */
  @GetMapping("/{fileId}/summary")
  @Operation(summary = "Get analysis summary for a file (202 while still processing)")
  public ResponseEntity<AnalysisSummaryResponse> getAnalysisSummary(@PathVariable UUID fileId) {
    log.info("GET /api/analysis/{}/summary", fileId);

    // Check file status first
    FileEntity file = fileService.getFileById(fileId);

    // Check analysis status
    AnalysisResultEntity analysis = analysisService.getAnalysisResultByFileId(fileId);

    if (analysis == null) {
      // No analysis record. If the file was reconciled to FAILED (analysis never ran — e.g. queue
      // overflow or a restart lost the in-memory task), surface the failure instead of polling
      // forever with 202.
      if (file.getStatus() == FileEntity.FileStatus.FAILED) {
        log.error("File {} is FAILED with no analysis record (never ran)", fileId);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
      }
      // Otherwise the file is still processing
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
   * Live analysis progress for a file still being analysed. Returns 200 with the current stage while
   * a run is in flight, or 204 No Content when nothing is being tracked (not started, already
   * finished, or dropped on a restart) — in which case the client falls back to its size estimate.
   */
  @GetMapping("/{fileId}/progress")
  @Operation(summary = "Live analysis progress (204 when no run is being tracked)")
  public ResponseEntity<AnalysisProgressResponse> getAnalysisProgress(@PathVariable UUID fileId) {
    return analysisProgressService
        .get(fileId)
        .map(ResponseEntity::ok)
        .orElseGet(() -> ResponseEntity.noContent().build());
  }

  /**
   * Get protocol statistics for a file Returns: - 200 OK: Analysis completed successfully (with
   * data) - 202 Accepted: Analysis still in progress - 500 Internal Server Error: Analysis failed -
   * 404 Not Found: File or analysis not found
   */
  @GetMapping("/{fileId}/protocols")
  @Operation(summary = "Get protocol statistics for a file (202 while still processing)")
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
}
