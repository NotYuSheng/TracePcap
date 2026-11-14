package com.tracepcap.signatures.controller;

import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.signatures.dto.RuleReapplyJobDto;
import com.tracepcap.signatures.dto.RuleSyncStatusDto;
import com.tracepcap.signatures.dto.StartReapplyRequest;
import com.tracepcap.signatures.service.RuleReapplyJobService;
import com.tracepcap.signatures.service.RuleSyncService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/** Whether captures are up to date with the rules, and Re-apply (#925 phase 2). */
@RestController
@RequiredArgsConstructor
@Tag(name = "Detection Rule Sync", description = "Staleness of rule matches, and re-applying rules")
public class RuleSyncController {

  private final RuleSyncService sync;
  private final RuleReapplyJobService jobs;

  @GetMapping("/detection-rules/status")
  @Operation(summary = "How many captures are out of date with the enabled rules")
  public RuleSyncStatusDto status() {
    return sync.overall();
  }

  @GetMapping("/detection-rules/stale-captures")
  @Operation(summary = "The captures out of date with at least one enabled rule, by id")
  public List<UUID> staleCaptures() {
    return sync.staleFiles();
  }

  @GetMapping("/files/{fileId}/rule-status")
  @Operation(summary = "Which enabled rules one capture is out of date for, or couldn't re-check")
  public RuleSyncStatusDto fileStatus(@PathVariable UUID fileId) {
    return sync.forFile(fileId);
  }

  @PostMapping("/rule-reapply-jobs")
  @Operation(
      summary = "Re-apply the rules to one capture, or to every out-of-date one (audited)",
      description =
          "Runs in the background; poll the job. 201 for a new job; 200 with the running job if"
              + " one is already running. Needs DETECTION_RULES_GLOBAL.")
  public ResponseEntity<RuleReapplyJobDto> start(@RequestBody(required = false) StartReapplyRequest request) {
    var started = jobs.start(request == null ? null : request.getFileId());
    return ResponseEntity.status(started.alreadyRunning() ? HttpStatus.OK : HttpStatus.CREATED).body(started.job());
  }

  @GetMapping("/rule-reapply-jobs")
  @Operation(summary = "The most recent Re-apply jobs, newest first")
  public List<RuleReapplyJobDto> recent() {
    return jobs.recent(10);
  }

  @GetMapping("/rule-reapply-jobs/{id}")
  @Operation(summary = "One Re-apply job and its progress")
  public RuleReapplyJobDto get(@PathVariable UUID id) {
    return jobs.get(id).orElseThrow(() -> new ResourceNotFoundException("Re-apply job not found: " + id));
  }
}
