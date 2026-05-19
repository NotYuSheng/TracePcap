package com.tracepcap.monitor.controller;

import com.tracepcap.monitor.dto.BaselineDefinitionDto;
import com.tracepcap.monitor.dto.CreateBaselineDefinitionRequest;
import com.tracepcap.monitor.service.BaselineService;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/monitor/networks/{networkId}/baseline/definitions")
@RequiredArgsConstructor
public class BaselineDefinitionController {

  private final BaselineService baselineService;

  @GetMapping
  public List<BaselineDefinitionDto> listDefinitions(@PathVariable UUID networkId) {
    return baselineService.listDefinitions(networkId);
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  public BaselineDefinitionDto createDefinition(
      @PathVariable UUID networkId,
      @Valid @RequestBody CreateBaselineDefinitionRequest request) {
    return baselineService.createDefinition(networkId, request);
  }

  @DeleteMapping("/{definitionId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void deleteDefinition(
      @PathVariable UUID networkId, @PathVariable UUID definitionId) {
    baselineService.deleteDefinition(networkId, definitionId);
  }
}
