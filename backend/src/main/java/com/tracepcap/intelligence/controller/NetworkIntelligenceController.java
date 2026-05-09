package com.tracepcap.intelligence.controller;

import com.tracepcap.intelligence.dto.ClusterGraphResponse;
import com.tracepcap.intelligence.dto.TopHostsResponse;
import com.tracepcap.intelligence.service.NetworkIntelligenceService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
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
      description = "Returns network hosts grouped into clusters by ASN, country, subnet, or device type. Suitable for large PCAPs with 10,000+ hosts.")
  public ResponseEntity<ClusterGraphResponse> getClusters(
      @PathVariable UUID fileId,
      @RequestParam(defaultValue = "asn") String groupBy) {

    log.info("GET /api/network/intelligence/{}/clusters?groupBy={}", fileId, groupBy);
    ClusterGraphResponse response = intelligenceService.computeClusters(fileId, groupBy);
    return ResponseEntity.ok(response);
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
