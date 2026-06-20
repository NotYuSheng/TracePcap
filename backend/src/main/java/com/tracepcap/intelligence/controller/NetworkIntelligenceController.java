package com.tracepcap.intelligence.controller;

import com.tracepcap.analysis.dto.ConversationFilterParams;
import com.tracepcap.intelligence.dto.ClusterGraphResponse;
import com.tracepcap.intelligence.dto.DnsQueryLogResponse;
import com.tracepcap.intelligence.dto.ServiceServerSummaryDto;
import com.tracepcap.intelligence.dto.TopHostsResponse;
import com.tracepcap.intelligence.dto.WebServerDetailResponse;
import com.tracepcap.intelligence.service.NetworkIntelligenceService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

@Slf4j
@Validated
@RestController
@RequestMapping("/api/network/intelligence")
@RequiredArgsConstructor
@Tag(name = "Network Intelligence", description = "Large-scale network topology clustering and host analytics")
public class NetworkIntelligenceController {

  private final NetworkIntelligenceService intelligenceService;

  @GetMapping("/{fileId}/clusters")
  @Operation(
      summary = "Get clustered network topology",
      description = "Returns network hosts grouped into clusters by ASN, country, subnet, or device type. Supports the same conversation filters as the conversations endpoint to pre-filter traffic before clustering.")
  public ResponseEntity<ClusterGraphResponse> getClusters(
      @PathVariable UUID fileId,
      @RequestParam(defaultValue = "asn") String groupBy,
      @Parameter(description = "Filter by IP address or hostname") @RequestParam(required = false) String ip,
      @Parameter(description = "Filter by port number (src or dst)") @RequestParam(required = false) @Min(0) @Max(65535) Integer port,
      @Parameter(description = "Comma-separated L4 protocols") @RequestParam(required = false) String protocols,
      @Parameter(description = "Comma-separated L7 protocols") @RequestParam(required = false) String l7Protocols,
      @Parameter(description = "Comma-separated application names") @RequestParam(required = false) String apps,
      @Parameter(description = "Comma-separated categories") @RequestParam(required = false) String categories,
      @Parameter(description = "Only conversations with flow risks") @RequestParam(required = false) Boolean hasRisks,
      @Parameter(description = "Comma-separated detected file types") @RequestParam(required = false) String fileTypes,
      @Parameter(description = "Comma-separated nDPI risk types") @RequestParam(required = false) String riskTypes,
      @Parameter(description = "Comma-separated custom signature rule names") @RequestParam(required = false) String customSignatures,
      @Parameter(description = "Filter by payload content (ASCII or hex)") @RequestParam(required = false) String payloadContains,
      @Parameter(description = "Comma-separated device types") @RequestParam(required = false) String deviceTypes,
      @Parameter(description = "Comma-separated ISO 3166-1 alpha-2 country codes") @RequestParam(required = false) String countries,
      @Parameter(description = "Comma-separated network label names (e.g. 'Office,DMZ')") @RequestParam(required = false) String networkLabels) {

    log.info("GET /api/network/intelligence/{}/clusters?groupBy={}", fileId, groupBy);

    ConversationFilterParams filterParams = ConversationFilterParams.builder()
        .ip(ip)
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
        .build();

    ClusterGraphResponse response = intelligenceService.computeClusters(fileId, groupBy, filterParams, splitComma(networkLabels));
    return ResponseEntity.ok(response);
  }

  private static List<String> splitComma(String value) {
    if (value == null || value.isBlank()) return List.of();
    return Arrays.stream(value.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
  }

  @GetMapping("/{fileId}/top-hosts")
  @Operation(
      summary = "Get top hosts by traffic volume",
      description = "Returns the top N hosts ranked by bytes, packets, conversations, or risk count.")
  public ResponseEntity<TopHostsResponse> getTopHosts(
      @PathVariable UUID fileId,
      @RequestParam(defaultValue = "bytes") String sortBy,
      @RequestParam(defaultValue = "100") int limit) {

    log.info("GET /api/network/intelligence/{}/top-hosts?sortBy={}&limit={}", fileId, sortBy, limit);
    int safeLimit = Math.min(limit, 500);
    TopHostsResponse response = intelligenceService.computeTopHosts(fileId, sortBy, safeLimit);
    return ResponseEntity.ok(response);
  }

  @GetMapping("/{fileId}/dns-servers")
  @Operation(
      summary = "List DNS servers and their resolution health",
      description = "Returns every host that answered DNS queries in the capture, with resolved vs. failed counts and an NXDOMAIN-based suspicious flag (possible DNS tunnelling / domain-generation algorithm).")
  public ResponseEntity<List<ServiceServerSummaryDto>> getDnsServers(@PathVariable UUID fileId) {
    log.info("GET /api/network/intelligence/{}/dns-servers", fileId);
    return ResponseEntity.ok(intelligenceService.computeDnsServers(fileId));
  }

  @GetMapping("/{fileId}/dns/{serverIp}")
  @Operation(
      summary = "Get the DNS query log for one DNS server",
      description = "Returns the per-domain query log (hostname queried, response code, resolved IPs, query count, resolvable) for the given DNS server, plus summary counts and the suspicious verdict.")
  public ResponseEntity<DnsQueryLogResponse> getDnsQueryLog(
      @PathVariable UUID fileId, @PathVariable String serverIp) {
    log.info("GET /api/network/intelligence/{}/dns/{}", fileId, serverIp);
    return ResponseEntity.ok(intelligenceService.computeDnsQueryLog(fileId, serverIp));
  }

  @GetMapping("/{fileId}/web-servers")
  @Operation(
      summary = "List web/API servers and their HTTP health",
      description = "Returns every host classified as a web/API server (includes HTTPS-only hosts), with success vs. error response counts and a 4xx-based suspicious flag (possible endpoint enumeration / scanning).")
  public ResponseEntity<List<ServiceServerSummaryDto>> getWebServers(@PathVariable UUID fileId) {
    log.info("GET /api/network/intelligence/{}/web-servers", fileId);
    return ResponseEntity.ok(intelligenceService.computeWebServers(fileId));
  }

  @GetMapping("/{fileId}/web/{serverIp}")
  @Operation(
      summary = "Get the HTTP endpoint log + detail for one web/API server",
      description = "Returns the per-endpoint log (method, path, status-class counts, content type) plus server software, content types and TLS metadata (cleartext HTTP only for endpoints; TLS detail for HTTPS).")
  public ResponseEntity<WebServerDetailResponse> getWebServerDetail(
      @PathVariable UUID fileId, @PathVariable String serverIp) {
    log.info("GET /api/network/intelligence/{}/web/{}", fileId, serverIp);
    return ResponseEntity.ok(intelligenceService.computeWebServerDetail(fileId, serverIp));
  }
}
