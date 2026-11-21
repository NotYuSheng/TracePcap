package com.tracepcap.insights.controller;

import com.tracepcap.governance.PermissionService;
import com.tracepcap.governance.PermissionAction;
import com.tracepcap.common.aijob.AiJobDto;
import com.tracepcap.common.aijob.AiJobService;
import com.tracepcap.insights.dto.GenerateInsightRequest;
import com.tracepcap.insights.service.NetworkInsightService;
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

/** Generating a network's insights in the background: the page doesn't wait on the model. */
@RestController
@RequiredArgsConstructor
@Tag(name = "Network Insights", description = "AI-generated insights for a monitored network")
public class InsightJobController {

  public static final String KIND = "INSIGHTS";

  private final PermissionService permissionService;

  private final AiJobService jobs;
  private final NetworkInsightService insights;

  @PostMapping("/monitor/networks/{networkId}/insight-jobs")
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Generate insights in the background",
      description = "Queues the insights and returns at once with the job WAITING. Check on it at /ai-jobs/{id}: DONE carries the new insight (whose own status says whether the model managed it). Asking again while one waits or runs returns that job.")
  public AiJobDto start(
      @PathVariable UUID networkId, @RequestBody(required = false) GenerateInsightRequest request) {
    permissionService.require(PermissionAction.ASK_AI);
    String name = insights.networkName(networkId);
    return jobs.submit(KIND, networkId, name, () -> insights.generateInsights(networkId, request));
  }
}
