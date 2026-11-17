package com.tracepcap.subnets.controller;

import com.tracepcap.common.aijob.AiJobDto;
import com.tracepcap.common.aijob.AiJobService;
import com.tracepcap.subnets.service.SubnetLabelSuggestionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Suggesting a subnet's label with AI in the background. */
@RestController
@RequiredArgsConstructor
@Tag(name = "Subnets", description = "User-defined subnet labels and auto-detection")
public class SubnetLabelJobController {

  public static final String KIND = "SUBNET_LABEL";

  private final AiJobService jobs;
  private final SubnetLabelSuggestionService suggestions;

  @PostMapping("/subnets/{id}/label-suggestion-jobs")
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Suggest a subnet label in the background",
      description = "Checks the subnet has members in the scanned captures (422 at once if not), then queues the suggestion and returns with the job WAITING. Check on it at /ai-jobs/{id}: DONE carries a label and description for the edit form (not saved). Scope with networkId, or to one capture with fileId.")
  public AiJobDto start(
      @PathVariable Long id,
      @RequestParam(required = false) UUID networkId,
      @RequestParam(required = false) UUID fileId) {
    SubnetLabelSuggestionService.Prepared p = suggestions.prepare(id, networkId, fileId);
    String key = "subnet:" + id + (fileId != null ? ":" + fileId : "");
    return jobs.submitFor(KIND, networkId, key, p.cidr(), p.suggestion());
  }
}
