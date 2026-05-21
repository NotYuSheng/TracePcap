package com.tracepcap.insights.controller;

import com.tracepcap.insights.dto.GenerateInsightRequest;
import com.tracepcap.insights.dto.NetworkInsightDto;
import com.tracepcap.insights.service.SnapshotInsightService;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/monitor/networks/{networkId}/snapshots/{snapshotId}/insights")
@RequiredArgsConstructor
public class SnapshotInsightController {

  private final SnapshotInsightService service;

  @GetMapping("/latest")
  public ResponseEntity<NetworkInsightDto> getLatest(@PathVariable UUID networkId,
      @PathVariable UUID snapshotId) {
    return service.getLatestInsight(snapshotId)
        .map(ResponseEntity::ok)
        .orElse(ResponseEntity.noContent().build());
  }

  @PostMapping("/generate")
  public ResponseEntity<NetworkInsightDto> generate(
      @PathVariable UUID networkId,
      @PathVariable UUID snapshotId,
      @RequestBody(required = false) GenerateInsightRequest req) {
    return ResponseEntity.ok(service.generateInsight(networkId, snapshotId, req));
  }
}
