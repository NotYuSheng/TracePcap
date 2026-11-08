package com.tracepcap.signatures.controller;

import com.tracepcap.signatures.dto.DetectionRuleDto;
import com.tracepcap.signatures.dto.DetectionRuleRequest;
import com.tracepcap.signatures.service.DetectionRuleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Rules for one monitored network (#925 phase 3). Their matches show when a capture is viewed in
 * this network. Edit and delete them at {@code /detection-rules/{id}} like any rule.
 */
@RestController
@RequestMapping("/monitor/networks/{networkId}/detection-rules")
@RequiredArgsConstructor
@Tag(name = "Network Detection Rules", description = "Detection rules that belong to one network")
public class NetworkRulesController {

  private final DetectionRuleService service;

  @GetMapping
  @Operation(summary = "This network's own rules")
  public List<DetectionRuleDto> list(@PathVariable UUID networkId) {
    return service.listNetwork(networkId);
  }

  @GetMapping("/suppressions")
  @Operation(summary = "The global rules switched off in this network's views")
  public List<com.tracepcap.signatures.dto.RuleSuppressionDto> suppressions(@PathVariable UUID networkId) {
    return service.listSuppressions(networkId);
  }

  @org.springframework.web.bind.annotation.PutMapping("/suppressions/{ruleId}")
  @Operation(
      summary = "Switch a global rule off in this network's views (audited, idempotent)",
      description = "The rule keeps running elsewhere; its matches are hidden when viewed in this network.")
  public List<com.tracepcap.signatures.dto.RuleSuppressionDto> suppress(
      @PathVariable UUID networkId, @PathVariable UUID ruleId) {
    service.setSuppressed(networkId, ruleId, true);
    return service.listSuppressions(networkId);
  }

  @org.springframework.web.bind.annotation.DeleteMapping("/suppressions/{ruleId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Operation(summary = "Switch a global rule back on in this network's views (audited)")
  public void unsuppress(@PathVariable UUID networkId, @PathVariable UUID ruleId) {
    service.setSuppressed(networkId, ruleId, false);
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Add a rule to this network (audited)",
      description =
          "Checked against each capture that joins the network from now on, and against the"
              + " network's existing captures on Re-apply.")
  public DetectionRuleDto create(@PathVariable UUID networkId, @Valid @RequestBody DetectionRuleRequest request) {
    return service.createForNetwork(networkId, request);
  }
}
