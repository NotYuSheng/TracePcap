package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.ConversationDetailResponse;
import com.tracepcap.analysis.dto.ConversationFilterParams;
import com.tracepcap.analysis.dto.ConversationResponse;
import com.tracepcap.analysis.service.AnalysisService;
import com.tracepcap.common.dto.PagedResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** REST controller for conversation operations */
@Slf4j
@RestController
@RequestMapping("/api/conversations")
@RequiredArgsConstructor
public class ConversationsController {

  private final AnalysisService analysisService;

  private static final DateTimeFormatter CSV_DT = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

  /** Get conversations for a file with optional filtering, sorting, and pagination */
  @GetMapping("/{fileId}")
  @Operation(summary = "Get conversations with filtering, sorting, and pagination")
  public ResponseEntity<PagedResponse<ConversationResponse>> getConversations(
      @PathVariable UUID fileId,
      @Parameter(description = "Page number (1-indexed)") @RequestParam(defaultValue = "1") int page,
      @Parameter(description = "Number of items per page") @RequestParam(defaultValue = "25") int pageSize,
      @Parameter(description = "Filter by IP address or hostname (src, dst, or hostname contains)") @RequestParam(required = false) String ip,
      @Parameter(description = "Comma-separated list of protocols to include") @RequestParam(required = false) String protocols,
      @Parameter(description = "Comma-separated list of application names to include") @RequestParam(required = false) String apps,
      @Parameter(description = "Comma-separated list of categories to include") @RequestParam(required = false) String categories,
      @Parameter(description = "When true, only conversations with flow risks are returned") @RequestParam(required = false) Boolean hasRisks,
      @Parameter(description = "Comma-separated list of detected file types to include") @RequestParam(required = false) String fileTypes,
      @Parameter(description = "Comma-separated list of nDPI risk types to include") @RequestParam(required = false) String riskTypes,
      @Parameter(description = "Field to sort by: srcIp, dstIp, packets, bytes, duration, startTime") @RequestParam(required = false) String sortBy,
      @Parameter(description = "Sort direction: asc (default) or desc") @RequestParam(required = false) String sortDir,
      @Parameter(description = "Legacy alias for ip param") @RequestParam(required = false) String search) {

    if (page < 1) page = 1;
    if (pageSize < 1 || pageSize > 100) pageSize = 25;

    ConversationFilterParams params = buildFilterParams(ip, protocols, apps, categories, hasRisks, fileTypes, riskTypes, sortBy, sortDir, search);

    log.info("GET /api/conversations/{} - page:{}, pageSize:{}, ip:{}, protocols:{}, apps:{}, categories:{}, hasRisks:{}, fileTypes:{}, riskTypes:{}, sortBy:{} {}",
        fileId, page, pageSize, params.getIp(), protocols, apps, categories, hasRisks, fileTypes, riskTypes, sortBy, sortDir);

    return ResponseEntity.ok(analysisService.getConversations(fileId, page, pageSize, params));
  }

  /** Returns the distinct detected file types found in packets for this file. */
  @GetMapping("/{fileId}/file-types")
  @Operation(summary = "List distinct detected file types for a file")
  public ResponseEntity<List<String>> getFileTypes(@PathVariable UUID fileId) {
    return ResponseEntity.ok(analysisService.getDistinctFileTypes(fileId));
  }

  /** Returns the distinct nDPI risk type strings present in at-risk conversations for this file. */
  @GetMapping("/{fileId}/risk-types")
  @Operation(summary = "List distinct nDPI risk types for a file")
  public ResponseEntity<List<String>> getRiskTypes(@PathVariable UUID fileId) {
    return ResponseEntity.ok(analysisService.getDistinctRiskTypes(fileId));
  }

  /** Export all matching conversations as CSV (no pagination, same filters as listing) */
  @GetMapping("/{fileId}/export")
  @Operation(summary = "Export filtered conversations as CSV")
  public void exportConversations(
      @PathVariable UUID fileId,
      @RequestParam(required = false) String ip,
      @RequestParam(required = false) String protocols,
      @RequestParam(required = false) String apps,
      @RequestParam(required = false) String categories,
      @RequestParam(required = false) Boolean hasRisks,
      @RequestParam(required = false) String fileTypes,
      @RequestParam(required = false) String riskTypes,
      @RequestParam(required = false) String sortBy,
      @RequestParam(required = false) String sortDir,
      @RequestParam(required = false) String search,
      HttpServletResponse response) throws IOException {

    ConversationFilterParams params = buildFilterParams(ip, protocols, apps, categories, hasRisks, fileTypes, riskTypes, sortBy, sortDir, search);
    List<ConversationResponse> rows = analysisService.getConversationsForExport(fileId, params);

    response.setContentType("text/csv");
    response.setHeader("Content-Disposition", "attachment; filename=\"conversations.csv\"");

    PrintWriter writer = response.getWriter();
    writer.println("srcIp,srcPort,dstIp,dstPort,protocol,appName,category,hostname,packetCount,totalBytes,durationMs,startTime,endTime,flowRisks");
    for (ConversationResponse r : rows) {
      String flowRisksValue = r.getFlowRisks() != null ? String.join("; ", r.getFlowRisks()) : "";
      writer.printf("%s,%s,%s,%s,%s,%s,%s,%s,%d,%d,%d,%s,%s,%s%n",
          escapeCsv(r.getSrcIp()), escapeCsv(r.getSrcPort()),
          escapeCsv(r.getDstIp()), escapeCsv(r.getDstPort()),
          escapeCsv(r.getProtocol()), escapeCsv(r.getAppName()),
          escapeCsv(r.getCategory()), escapeCsv(r.getHostname()),
          r.getPacketCount(), r.getTotalBytes(), r.getDurationMs(),
          r.getStartTime() != null ? escapeCsv(CSV_DT.format(r.getStartTime())) : "",
          r.getEndTime()   != null ? escapeCsv(CSV_DT.format(r.getEndTime()))   : "",
          escapeCsv(flowRisksValue));
    }
    writer.flush();
  }

  /** Get detailed conversation info including all packets */
  @GetMapping("/detail/{conversationId}")
  @Operation(summary = "Get conversation details with packet stream")
  public ResponseEntity<ConversationDetailResponse> getConversationDetail(
      @PathVariable UUID conversationId) {
    log.info("GET /api/conversations/detail/{}", conversationId);
    return ResponseEntity.ok(analysisService.getConversationDetail(conversationId));
  }

  /** Shared helper — builds a {@link ConversationFilterParams} from raw request parameters. */
  private static ConversationFilterParams buildFilterParams(
      String ip, String protocols, String apps, String categories,
      Boolean hasRisks, String fileTypes, String riskTypes,
      String sortBy, String sortDir, String search) {
    // Backward compat: legacy ?search= param maps to the ip filter
    String resolvedIp = (ip != null) ? ip : search;
    return ConversationFilterParams.builder()
        .ip(resolvedIp)
        .protocols(splitComma(protocols))
        .apps(splitComma(apps))
        .categories(splitComma(categories))
        .hasRisks(hasRisks)
        .fileTypes(splitComma(fileTypes))
        .riskTypes(splitComma(riskTypes))
        .sortBy(sortBy)
        .sortDir(sortDir)
        .build();
  }

  private static List<String> splitComma(String value) {
    if (value == null || value.isBlank()) return List.of();
    return Arrays.stream(value.split(","))
        .map(String::trim)
        .filter(s -> !s.isEmpty())
        .toList();
  }

  /**
   * Escapes a value for safe inclusion in a CSV field.
   * Fields containing commas, double-quotes, or newlines are wrapped in double-quotes,
   * and any embedded double-quotes are doubled per RFC 4180.
   */
  private static String escapeCsv(Object value) {
    if (value == null) return "";
    String s = value.toString();
    if (s.contains(",") || s.contains("\"") || s.contains("\n") || s.contains("\r")) {
      return "\"" + s.replace("\"", "\"\"") + "\"";
    }
    return s;
  }
}
