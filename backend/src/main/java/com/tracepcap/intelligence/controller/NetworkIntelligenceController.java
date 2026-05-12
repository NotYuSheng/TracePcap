package com.tracepcap.intelligence.controller;

import com.tracepcap.analysis.dto.ConversationFilterParams;
import com.tracepcap.intelligence.dto.ClusterGraphResponse;
import com.tracepcap.intelligence.dto.TopHostsResponse;
import com.tracepcap.intelligence.service.NetworkIntelligenceService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@Slf4j
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
      @Parameter(description = "Filter by port number (src or dst)") @RequestParam(required = false) Integer port,
      @Parameter(description = "Comma-separated L4 protocols") @RequestParam(required = false) String protocols,
      @Parameter(description = "Comma-separated L7 protocols") @RequestParam(required = false) String l7Protocols,
      @Parameter(description = "Comma-separated application names") @RequestParam(required = false) String apps,
      @Parameter(description = "Comma-separated categories") @RequestParam(required = false) String categories,
      @Parameter(description = "Only conversations with flow risks") @RequestParam(required = false) Boolean hasRisks,
      @Parameter(description = "Comma-separated detected file types") @RequestParam(required = false) String fileTypes,
      @Parameter(description = "Comma-separated nDPI risk types") @RequestParam(required = false) String riskTypes,
      @Parameter(description = "Comma-separated custom signature rule names") @RequestParam(required = false) String customSignatures,
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
}
