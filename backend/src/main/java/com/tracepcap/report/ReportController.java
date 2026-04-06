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
}
