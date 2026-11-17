package com.tracepcap.insights.controller;

import com.tracepcap.common.aijob.AiJobDto;
import com.tracepcap.common.aijob.AiJobService;
import com.tracepcap.insights.dto.GenerateInsightRequest;
import com.tracepcap.insights.service.NetworkInsightService;
import com.tracepcap.insights.service.SnapshotInsightService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Generating one capture's insights, within a monitored network, in the background. */
@RestController
@RequiredArgsConstructor
@Tag(name = "Snapshot Insights", description = "AI-generated insights for a single snapshot")
public class SnapshotInsightJobController {

  public static final String KIND = "SNAPSHOT_INSIGHTS";

  private final AiJobService jobs;
  private final SnapshotInsightService snapshots;
  private final NetworkInsightService networks;

  @PostMapping("/monitor/networks/{networkId}/snapshots/{snapshotId}/insight-jobs")
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Generate a capture's insights in the background",
      description = "Queues the insights and returns at once with the job WAITING. Check on it at /ai-jobs/{id}: DONE carries the new insight. Asking again while one waits or runs returns that job.")
  public AiJobDto start(
      @PathVariable UUID networkId,
      @PathVariable UUID snapshotId,
      @RequestBody(required = false) GenerateInsightRequest request) {
    String name = networks.networkName(networkId);
    return jobs.submitFor(KIND, networkId, snapshotId.toString(), name,
        () -> snapshots.generateInsight(networkId, snapshotId, request));
  }
}
