package com.tracepcap.report;

import io.swagger.v3.oas.annotations.Operation;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

@Slf4j
@RestController
@RequestMapping("/api/files")
@RequiredArgsConstructor
public class ReportController {

  private final ReportService reportService;
  private final CompareReportService compareReportService;

  @PostMapping("/{fileId}/report")
  @Operation(summary = "Generate and download a PDF analysis report for a PCAP file")
  public ResponseEntity<StreamingResponseBody> downloadReport(
      @PathVariable UUID fileId, @RequestBody(required = false) ReportRequest request) {

    log.info("POST /api/files/{}/report", fileId);

    ReportRequest req = request != null ? request : new ReportRequest();
    StreamingResponseBody body = out -> reportService.generateReport(fileId, req, out);

    return ResponseEntity.ok()
        .header(
            HttpHeaders.CONTENT_DISPOSITION,
            ContentDisposition.builder("attachment")
                .filename("tracepcap-report-" + fileId + ".pdf")
                .build()
                .toString())
        .contentType(MediaType.APPLICATION_PDF)
        .body(body);
  }

  @PostMapping("/compare/report")
  @Operation(summary = "Generate and download a PDF compare-topology report for multiple PCAP files")
  public ResponseEntity<StreamingResponseBody> downloadCompareReport(
      @RequestBody CompareReportRequest request) {

    log.info("POST /api/files/compare/report — {} files", request.getFileIds() != null ? request.getFileIds().size() : 0);

    StreamingResponseBody body = out -> compareReportService.generateReport(request, out);

    // Build filename: tracepcap-compare-report-<id1>-<id2>-....pdf
    String ids = request.getFileIds() != null
        ? request.getFileIds().stream().map(UUID::toString).collect(java.util.stream.Collectors.joining("-"))
        : "unknown";
    String filename = "tracepcap-compare-report-" + ids + ".pdf";

    return ResponseEntity.ok()
        .header(
            HttpHeaders.CONTENT_DISPOSITION,
            ContentDisposition.builder("attachment")
                .filename(filename)
                .build()
                .toString())
        .contentType(MediaType.APPLICATION_PDF)
        .body(body);
  }
}
