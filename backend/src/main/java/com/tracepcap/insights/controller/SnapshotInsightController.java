package com.tracepcap.insights.controller;

import com.tracepcap.insights.dto.GenerateInsightRequest;
import com.tracepcap.insights.dto.NetworkInsightDto;
import com.tracepcap.insights.service.SnapshotInsightService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/monitor/networks/{networkId}/snapshots/{snapshotId}/insights")
@RequiredArgsConstructor
@Tag(name = "Snapshot Insights", description = "AI-generated insights for a single snapshot")
public class SnapshotInsightController {

  private final SnapshotInsightService service;

  @GetMapping("/latest")
  @Operation(summary = "Get the latest generated insight for a snapshot")
  public ResponseEntity<NetworkInsightDto> getLatest(@PathVariable UUID networkId,
      @PathVariable UUID snapshotId) {
    return service.getLatestInsight(snapshotId)
        .map(ResponseEntity::ok)
        .orElse(ResponseEntity.noContent().build());
  }

  @PostMapping
  @Operation(summary = "Generate a new insight for a snapshot")
  public ResponseEntity<NetworkInsightDto> generate(
      @PathVariable UUID networkId,
      @PathVariable UUID snapshotId,
      @RequestBody(required = false) GenerateInsightRequest req) {
    return ResponseEntity.ok(service.generateInsight(networkId, snapshotId, req));
  }
}
