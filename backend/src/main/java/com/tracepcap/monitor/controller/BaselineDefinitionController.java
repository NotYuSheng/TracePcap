package com.tracepcap.monitor.controller;

import com.tracepcap.monitor.dto.BaselineDefinitionDto;
import com.tracepcap.monitor.dto.CreateBaselineDefinitionRequest;
import com.tracepcap.monitor.service.BaselineService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/monitor/networks/{networkId}/baseline/definitions")
@RequiredArgsConstructor
@Tag(
    name = "Monitor Baseline Definitions",
    description = "Baseline rules used to detect drift in a monitored network")
public class BaselineDefinitionController {

  private final BaselineService baselineService;

  @GetMapping
  @Operation(summary = "List baseline definitions for a network")
  public List<BaselineDefinitionDto> listDefinitions(@PathVariable UUID networkId) {
    return baselineService.listDefinitions(networkId);
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(summary = "Create a baseline definition")
  public BaselineDefinitionDto createDefinition(
      @PathVariable UUID networkId,
      @Valid @RequestBody CreateBaselineDefinitionRequest request) {
    return baselineService.createDefinition(networkId, request);
  }

  @DeleteMapping("/{definitionId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Operation(summary = "Delete a baseline definition")
  public void deleteDefinition(
      @PathVariable UUID networkId, @PathVariable UUID definitionId) {
    baselineService.deleteDefinition(networkId, definitionId);
  }
}
