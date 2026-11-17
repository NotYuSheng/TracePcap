package com.tracepcap.insights.controller;

import com.tracepcap.common.aijob.AiJobDto;
import com.tracepcap.common.aijob.AiJobService;
import com.tracepcap.insights.dto.RoleSuggestionJobRequest;
import com.tracepcap.insights.service.NodeRoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Suggesting a host's role with AI in the background: closing the host card doesn't lose it. */
@RestController
@RequiredArgsConstructor
@Tag(name = "Node Roles", description = "User-assigned roles for network entities (hosts/subnets)")
public class RoleSuggestionJobController {

  public static final String KIND = "ROLE_SUGGESTION";
  public static final String PREVIEW_KIND = "ROLE_PREVIEW";

  private final AiJobService jobs;
  private final NodeRoleService roles;

  @PostMapping("/node-roles/suggestion-jobs")
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Suggest a role in the background",
      description = "Queues the suggestion and returns at once with the job WAITING. Check on it at /ai-jobs/{id}: DONE carries the saved role (or, with preview, a label and description for the editor, not saved); FAILED with why, including when there's too little traffic to say. Asking again while one waits or runs returns that job.")
  public AiJobDto start(@Valid @RequestBody RoleSuggestionJobRequest r) {
    String key = r.getEntityType() + ":" + r.getEntityKey();
    return r.isPreview()
        ? jobs.submitFor(PREVIEW_KIND, r.getFileId(), key, r.getEntityKey(),
            () -> roles.suggestRolePreview(r.getEntityType(), r.getEntityKey(), r.getFileId()))
        : jobs.submitFor(KIND, r.getFileId(), key, r.getEntityKey(),
            () -> roles.suggestRole(r.getEntityType(), r.getEntityKey(), r.getFileId()));
  }
}
