package com.tracepcap.insights.controller;

import com.tracepcap.insights.dto.GenerateInsightRequest;
import com.tracepcap.insights.dto.NetworkInsightDto;
import com.tracepcap.insights.service.NetworkInsightService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/monitor/networks/{networkId}/insights")
@RequiredArgsConstructor
@Tag(name = "Network Insights", description = "AI-generated insights for a monitored network")
public class NetworkInsightController {

  private final NetworkInsightService service;

  @GetMapping("/latest")
  @Operation(summary = "Get the latest generated insight for a network")
  public ResponseEntity<NetworkInsightDto> getLatest(@PathVariable UUID networkId) {
    return service.getLatestInsight(networkId)
        .map(ResponseEntity::ok)
        .orElse(ResponseEntity.noContent().build());
  }

  @PostMapping
  @Operation(summary = "Generate a new insight for a network")
  public ResponseEntity<NetworkInsightDto> generate(
      @PathVariable UUID networkId,
      @RequestBody(required = false) GenerateInsightRequest req) {
    return ResponseEntity.ok(service.generateInsights(networkId, req));
  }
}
