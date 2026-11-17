package com.tracepcap.common.aijob;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * AI work running in the background. Each kind is started from its own resource (a capture's
 * {@code story-jobs}, a network's {@code insight-jobs}); this is where any of them is checked on.
 */
@RestController
@RequestMapping("/ai-jobs")
@RequiredArgsConstructor
@Tag(name = "AI jobs", description = "AI work running in the background, one job at a time")
public class AiJobController {

  private final AiJobService jobs;

  @GetMapping
  @Operation(
      summary = "What the model is working on",
      description = "Waiting and running jobs first, in the order they'll run, then those finished in the last 30 minutes. Results are left out; get a job by id for its result.")
  public List<AiJobDto> list(
      @RequestParam(required = false) String kind,
      @RequestParam(required = false) UUID subjectId,
      @RequestParam(required = false) String subjectKey) {
    return jobs.list(kind, subjectId, subjectKey);
  }

  @GetMapping("/{jobId}")
  @Operation(
      summary = "One job's progress or result",
      description = "WAITING with its place in line, RUNNING, then DONE with the result or FAILED with why.")
  public AiJobDto get(@PathVariable UUID jobId) {
    return jobs.get(jobId);
  }

  @PostMapping("/{jobId}/cancel")
  @Operation(
      summary = "Cancel a waiting job",
      description = "Takes it out of line. A running job can't be cancelled (400); only whoever asked, or an admin, can cancel (403). Returns the job, now CANCELLED.")
  public AiJobDto cancel(@PathVariable UUID jobId) {
    return jobs.cancel(jobId);
  }
}
