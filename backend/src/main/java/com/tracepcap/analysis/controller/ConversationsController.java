package com.tracepcap.analysis.controller;

import com.tracepcap.analysis.dto.ConversationDetailResponse;
import com.tracepcap.analysis.dto.ConversationFilterParams;
import com.tracepcap.analysis.dto.ConversationResponse;
import com.tracepcap.analysis.dto.SessionResponse;
import com.tracepcap.analysis.service.AnalysisService;
import com.tracepcap.analysis.service.SessionReconstructionService;
import com.tracepcap.common.dto.PagedResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.OutputStream;
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
  private final SessionReconstructionService sessionReconstructionService;

  private static final DateTimeFormatter CSV_DT = DateTimeFormatter.ISO_LOCAL_DATE_TIME;

  /** Get conversations for a file with optional filtering, sorting, and pagination */
  @GetMapping("/{fileId}")
  @Operation(summary = "Get conversations with filtering, sorting, and pagination")
  public ResponseEntity<PagedResponse<ConversationResponse>> getConversations(
      @PathVariable UUID fileId,
      @Parameter(description = "Page number (1-indexed)") @RequestParam(defaultValue = "1")
          int page,
      @Parameter(description = "Number of items per page") @RequestParam(defaultValue = "25")
          int pageSize,
      @Parameter(description = "Filter by IP address or hostname (src, dst, or hostname contains)")
          @RequestParam(required = false)
          String ip,
      @Parameter(description = "Filter by port number (src or dst)") @RequestParam(required = false)
          Integer port,
      @Parameter(description = "Comma-separated list of L4 protocols to include")
          @RequestParam(required = false)
          String protocols,
      @Parameter(description = "Comma-separated list of L7 protocols (tshark) to include")
          @RequestParam(required = false)
          String l7Protocols,
      @Parameter(description = "Comma-separated list of application names to include")
          @RequestParam(required = false)
          String apps,
      @Parameter(description = "Comma-separated list of categories to include")
          @RequestParam(required = false)
          String categories,
      @Parameter(description = "When true, only conversations with flow risks are returned")
          @RequestParam(required = false)
          Boolean hasRisks,
      @Parameter(description = "Comma-separated list of detected file types to include")
          @RequestParam(required = false)
          String fileTypes,
      @Parameter(description = "Comma-separated list of nDPI risk types to include")
          @RequestParam(required = false)
          String riskTypes,
      @Parameter(description = "Comma-separated list of custom signature rule names to include")
          @RequestParam(required = false)
          String customSignatures,
      @Parameter(
              description =
                  "Filter conversations whose payload contains this pattern (ASCII or hex, e.g."
                      + " 'GET /admin', '0x474554', '47 45 54')")
          @RequestParam(required = false)
          String payloadContains,
      @Parameter(
              description = "Field to sort by: srcIp, dstIp, packets, bytes, duration, startTime")
          @RequestParam(required = false)
          String sortBy,
      @Parameter(description = "Sort direction: asc (default) or desc")
          @RequestParam(required = false)
          String sortDir,
      @Parameter(description = "Legacy alias for ip param") @RequestParam(required = false)
          String search,
      @Parameter(
              description =
                  "Comma-separated list of device types to include (ROUTER, MOBILE,"
                      + " LAPTOP_DESKTOP, SERVER, IOT, UNKNOWN, or custom)")
          @RequestParam(required = false)
          String deviceTypes,
      @Parameter(description = "Comma-separated list of ISO 3166-1 alpha-2 country codes to include (e.g. US,CN,SG)")
          @RequestParam(required = false)
          String countries) {

    if (page < 1) page = 1;
    if (pageSize < 1) pageSize = 25;
    if (pageSize > 10000) pageSize = 10000;

    ConversationFilterParams params =
        buildFilterParams(
            ip,
            port,
            protocols,
            l7Protocols,
            apps,
            categories,
            hasRisks,
            fileTypes,
            riskTypes,
            customSignatures,
            payloadContains,
            sortBy,
            sortDir,
            search,
            deviceTypes,
            countries);

    log.info(
        "GET /api/conversations/{} - page:{}, pageSize:{}, ip:{}, port:{}, protocols:{}, l7Protocols:{}, apps:{}, categories:{}, hasRisks:{}, fileTypes:{}, riskTypes:{}, sortBy:{} {}",
        fileId,
        page,
        pageSize,
        params.getIp(),
        port,
        protocols,
        l7Protocols,
        apps,
        categories,
        hasRisks,
        fileTypes,
        riskTypes,
        sortBy,
        sortDir);

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

  /** Returns the distinct custom signature rule names triggered for this file. */
  @GetMapping("/{fileId}/custom-signatures")
  @Operation(summary = "List distinct custom signature rule names for a file")
  public ResponseEntity<List<String>> getCustomSignatures(@PathVariable UUID fileId) {
    return ResponseEntity.ok(analysisService.getDistinctCustomSignatures(fileId));
  }

  /** Returns the distinct country codes seen in external IPs for this file, as "CC|Country" strings. */
  @GetMapping("/{fileId}/countries")
  @Operation(summary = "List distinct country codes seen in external IPs for a file")
  public ResponseEntity<List<String>> getCountries(@PathVariable UUID fileId) {
    return ResponseEntity.ok(analysisService.getDistinctCountries(fileId));
  }

  /** Export all matching conversations as CSV (no pagination, same filters as listing) */
  @GetMapping("/{fileId}/export")
  @Operation(summary = "Export filtered conversations as CSV")
  public void exportConversations(
      @PathVariable UUID fileId,
      @RequestParam(required = false) String ip,
      @RequestParam(required = false) Integer port,
      @RequestParam(required = false) String protocols,
      @RequestParam(required = false) String l7Protocols,
      @RequestParam(required = false) String apps,
      @RequestParam(required = false) String categories,
      @RequestParam(required = false) Boolean hasRisks,
      @RequestParam(required = false) String fileTypes,
      @RequestParam(required = false) String riskTypes,
      @RequestParam(required = false) String customSignatures,
      @RequestParam(required = false) String payloadContains,
      @RequestParam(required = false) String sortBy,
      @RequestParam(required = false) String sortDir,
      @RequestParam(required = false) String search,
      @RequestParam(required = false) String deviceTypes,
      @RequestParam(required = false) String countries,
      HttpServletResponse response)
      throws IOException {

    ConversationFilterParams params =
        buildFilterParams(
            ip,
            port,
            protocols,
            l7Protocols,
            apps,
            categories,
            hasRisks,
            fileTypes,
            riskTypes,
            customSignatures,
            payloadContains,
            sortBy,
            sortDir,
            search,
            deviceTypes,
            countries);
    List<ConversationResponse> rows = analysisService.getConversationsForExport(fileId, params);

    response.setContentType("text/csv");
    response.setHeader("Content-Disposition", "attachment; filename=\"conversations.csv\"");

    PrintWriter writer = response.getWriter();
    writer.println(
        "srcIp,srcPort,dstIp,dstPort,protocol,appName,category,hostname,packetCount,totalBytes,durationMs,startTime,endTime,flowRisks,customSignatures");
    for (ConversationResponse r : rows) {
      String flowRisksValue = r.getFlowRisks() != null ? String.join("; ", r.getFlowRisks()) : "";
      String customSigsValue =
          r.getCustomSignatures() != null ? String.join("; ", r.getCustomSignatures()) : "";
      writer.printf(
          "%s,%s,%s,%s,%s,%s,%s,%s,%d,%d,%d,%s,%s,%s,%s%n",
          escapeCsv(r.getSrcIp()),
          escapeCsv(r.getSrcPort()),
          escapeCsv(r.getDstIp()),
          escapeCsv(r.getDstPort()),
          escapeCsv(r.getProtocol()),
          escapeCsv(r.getAppName()),
          escapeCsv(r.getCategory()),
          escapeCsv(r.getHostname()),
          r.getPacketCount(),
          r.getTotalBytes(),
          r.getDurationMs(),
          r.getStartTime() != null ? escapeCsv(CSV_DT.format(r.getStartTime())) : "",
          r.getEndTime() != null ? escapeCsv(CSV_DT.format(r.getEndTime())) : "",
          escapeCsv(flowRisksValue),
          escapeCsv(customSigsValue));
    }
    writer.flush();
  }

  /** Export all matching conversations as PCAP (no pagination, same filters as listing) */
  @GetMapping("/{fileId}/export-pcap")
  @Operation(summary = "Export filtered conversations as PCAP")
  public void exportConversationsAsPcap(
      @PathVariable UUID fileId,
      @RequestParam(required = false) String ip,
      @RequestParam(required = false) Integer port,
      @RequestParam(required = false) String protocols,
      @RequestParam(required = false) String l7Protocols,
      @RequestParam(required = false) String apps,
      @RequestParam(required = false) String categories,
      @RequestParam(required = false) Boolean hasRisks,
      @RequestParam(required = false) String fileTypes,
      @RequestParam(required = false) String riskTypes,
      @RequestParam(required = false) String customSignatures,
      @RequestParam(required = false) String payloadContains,
      @RequestParam(required = false) String sortBy,
      @RequestParam(required = false) String sortDir,
      @RequestParam(required = false) String search,
      @RequestParam(required = false) String deviceTypes,
      @RequestParam(required = false) String countries,
      HttpServletResponse response)
      throws IOException {

    ConversationFilterParams params =
        buildFilterParams(
            ip, port, protocols, l7Protocols, apps, categories, hasRisks, fileTypes, riskTypes,
            customSignatures, payloadContains, sortBy, sortDir, search, deviceTypes, countries);

    String filename = analysisService.getBulkPcapFilename(fileId);
    response.setContentType("application/vnd.tcpdump.pcap");
    response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

    try (OutputStream out = response.getOutputStream()) {
      analysisService.exportConversationsAsPcap(fileId, params, out);
    }
  }

  /** Reconstruct the full TCP/UDP session for a conversation and decode the application payload. */
  @GetMapping("/{conversationId}/session")
  @Operation(summary = "Reconstruct TCP/UDP session with application-layer payload decoding")
  public ResponseEntity<SessionResponse> getSession(@PathVariable UUID conversationId) {
    log.info("GET /api/conversations/{}/session", conversationId);
    return ResponseEntity.ok(sessionReconstructionService.reconstruct(conversationId));
  }

  /** Get detailed conversation info including all packets */
  @GetMapping("/detail/{conversationId}")
  @Operation(summary = "Get conversation details with packet stream")
  public ResponseEntity<ConversationDetailResponse> getConversationDetail(
      @PathVariable UUID conversationId) {
    log.info("GET /api/conversations/detail/{}", conversationId);
    return ResponseEntity.ok(analysisService.getConversationDetail(conversationId));
  }

  /** Export a single conversation as a PCAP file filtered from the original capture. */
  @GetMapping("/detail/{conversationId}/export-pcap")
  @Operation(summary = "Export a single conversation as PCAP")
  public void exportConversationAsPcap(
      @PathVariable UUID conversationId, HttpServletResponse response) throws IOException {
    log.info("GET /api/conversations/detail/{}/export-pcap", conversationId);
    String filename = analysisService.getConversationPcapFilename(conversationId);
    response.setContentType("application/vnd.tcpdump.pcap");
    response.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");
    try (OutputStream out = response.getOutputStream()) {
      analysisService.exportConversationAsPcap(conversationId, out);
    }
  }

  /** Shared helper — builds a {@link ConversationFilterParams} from raw request parameters. */
  private static ConversationFilterParams buildFilterParams(
      String ip,
      Integer port,
      String protocols,
      String l7Protocols,
      String apps,
      String categories,
      Boolean hasRisks,
      String fileTypes,
      String riskTypes,
      String customSignatures,
      String payloadContains,
      String sortBy,
      String sortDir,
      String search,
      String deviceTypes,
      String countries) {
    String resolvedIp = (ip != null) ? ip : search;
    return ConversationFilterParams.builder()
        .ip(resolvedIp)
        .port(port)
        .protocols(splitComma(protocols))
        .l7Protocols(splitComma(l7Protocols))
        .apps(splitComma(apps))
        .categories(splitComma(categories))
        .hasRisks(hasRisks)
        .fileTypes(splitComma(fileTypes))
        .riskTypes(splitComma(riskTypes))
        .customSignatures(splitComma(customSignatures))
        .payloadContains(payloadContains)
        .deviceTypes(splitComma(deviceTypes))
        .countries(splitComma(countries))
        .sortBy(sortBy)
        .sortDir(sortDir)
        .build();
  }

  private static List<String> splitComma(String value) {
    if (value == null || value.isBlank()) return List.of();
    return Arrays.stream(value.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
  }

  /**
   * Escapes a value for safe inclusion in a CSV field. Fields containing commas, double-quotes, or
   * newlines are wrapped in double-quotes, and any embedded double-quotes are doubled per RFC 4180.
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
