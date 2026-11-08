package com.tracepcap.signatures.controller;

import com.tracepcap.signatures.dto.DetectionRuleDto;
import com.tracepcap.signatures.dto.DetectionRuleRequest;
import com.tracepcap.signatures.dto.RuleImportRequest;
import com.tracepcap.signatures.dto.RuleImportResult;
import com.tracepcap.signatures.service.DetectionRuleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Custom detection rules (#925). Global scope; edits need DETECTION_RULES_GLOBAL and are audited. */
@RestController
@RequestMapping("/detection-rules")
@RequiredArgsConstructor
@Tag(name = "Detection Rules", description = "Custom detection rules that flag conversations")
public class DetectionRulesController {

  private final DetectionRuleService service;

  @GetMapping
  @Operation(
      summary = "List the global detection rules, by name",
      description = "With fileId, also that capture's own rules (scope CAPTURE): every rule that labels it.")
  public List<DetectionRuleDto> list(@org.springframework.web.bind.annotation.RequestParam(required = false) UUID fileId) {
    return fileId == null ? service.listGlobal() : service.listForFile(fileId);
  }

  @PostMapping("/{id}/promotions")
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(
      summary = "Promote a capture rule to a global rule (audited)",
      description =
          "Creates a linked global copy, checked against the source capture at once. Needs"
              + " DETECTION_RULES_GLOBAL, and DETECTION_RULES_CAPTURE too when the original is removed.")
  public DetectionRuleDto promote(@PathVariable UUID id, @RequestBody(required = false) com.tracepcap.signatures.dto.PromoteRuleRequest request) {
    return service.promote(id, request == null || request.isKeepOriginal());
  }

  @GetMapping("/{id}")
  @Operation(summary = "Get one detection rule")
  public DetectionRuleDto get(@PathVariable UUID id) {
    return service.get(id);
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(summary = "Create a global detection rule (audited)")
  public DetectionRuleDto create(@Valid @RequestBody DetectionRuleRequest request) {
    return service.create(request);
  }

  @PutMapping("/{id}")
  @Operation(summary = "Replace a detection rule (audited; bumps its version if anything changed)")
  public DetectionRuleDto update(@PathVariable UUID id, @Valid @RequestBody DetectionRuleRequest request) {
    return service.update(id, request);
  }

  @DeleteMapping("/{id}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Operation(summary = "Delete a detection rule (audited)")
  public void delete(@PathVariable UUID id) {
    service.delete(id);
  }

  @GetMapping(value = "/export", produces = "application/yaml")
  @Operation(
      summary = "Download every global rule as a YAML file",
      description = "For backups and for moving rules between installs. Import reads the same format.")
  public ResponseEntity<byte[]> export() {
    return ResponseEntity.ok()
        .contentType(MediaType.parseMediaType("application/yaml"))
        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"tracepcap-detection-rules.yml\"")
        .body(service.exportYaml().getBytes(StandardCharsets.UTF_8));
  }

  @PostMapping("/import")
  @Operation(
      summary = "Import a YAML rules file (audited, all or nothing)",
      description =
          "Accepts an export or an old signatures.yml. Rules are matched by name. MERGE adds and"
              + " updates; REPLACE also deletes global rules the file doesn't contain. One invalid"
              + " rule rejects the whole file, with validationErrors keyed by rule.")
  public RuleImportResult importRules(@Valid @RequestBody RuleImportRequest request) {
    return service.importYaml(request);
  }
}
