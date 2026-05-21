package com.tracepcap.insights.controller;

import com.tracepcap.insights.dto.GenerateInsightRequest;
import com.tracepcap.insights.dto.NetworkInsightDto;
import com.tracepcap.insights.service.NetworkInsightService;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/monitor/networks/{networkId}/insights")
@RequiredArgsConstructor
public class NetworkInsightController {

  private final NetworkInsightService service;

  @GetMapping("/latest")
  public ResponseEntity<NetworkInsightDto> getLatest(@PathVariable UUID networkId) {
    return service.getLatestInsight(networkId)
        .map(ResponseEntity::ok)
        .orElse(ResponseEntity.noContent().build());
  }

  @PostMapping("/generate")
  public ResponseEntity<NetworkInsightDto> generate(
      @PathVariable UUID networkId,
      @RequestBody(required = false) GenerateInsightRequest req) {
    return ResponseEntity.ok(service.generateInsights(networkId, req));
  }
}
