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
 * Rules for one capture (#925 phase 3). They apply wherever the capture is viewed. Edit and delete
 * them at {@code /detection-rules/{id}} like any rule.
 */
@RestController
@RequestMapping("/files/{fileId}/detection-rules")
@RequiredArgsConstructor
@Tag(name = "Capture Detection Rules", description = "Detection rules that belong to one capture")
public class CaptureRulesController {

  private final DetectionRuleService service;

  @GetMapping
  @Operation(summary = "This capture's own rules")
  public List<DetectionRuleDto> list(@PathVariable UUID fileId) {
    return service.listCapture(fileId);
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(summary = "Add a rule to this capture; it's checked at once (audited)")
  public DetectionRuleDto create(@PathVariable UUID fileId, @Valid @RequestBody DetectionRuleRequest request) {
    return service.createForCapture(fileId, request);
  }
}
