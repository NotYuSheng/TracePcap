package com.tracepcap.subnets.controller;

import com.tracepcap.subnets.dto.SubnetDefinitionDto;
import com.tracepcap.subnets.dto.SubnetLabelSuggestionDto;
import com.tracepcap.subnets.dto.UpsertSubnetRequest;
import com.tracepcap.subnets.service.SubnetLabelSuggestionService;
import com.tracepcap.subnets.service.SubnetService;
import com.tracepcap.subnets.service.SubnetStalenessService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/subnets")
@RequiredArgsConstructor
@Tag(name = "Subnets", description = "User-defined subnet labels and auto-detection")
public class SubnetController {

  private final SubnetService subnetService;
  private final SubnetLabelSuggestionService subnetLabelSuggestionService;
  private final SubnetStalenessService subnetStalenessService;

  @GetMapping
  @Operation(summary = "List defined subnets")
  public ResponseEntity<List<SubnetDefinitionDto>> list() {
    return ResponseEntity.ok(subnetService.list());
  }

  @PostMapping
  @Operation(summary = "Create or update a subnet definition")
  public ResponseEntity<SubnetDefinitionDto> upsert(@RequestBody UpsertSubnetRequest req) {
    return ResponseEntity.ok(subnetService.upsert(req));
  }

  @PostMapping("/detected")
  @Operation(summary = "Persist an auto-detected subnet")
  public ResponseEntity<SubnetDefinitionDto> saveDetected(@RequestBody UpsertSubnetRequest req) {
    return ResponseEntity.ok(subnetService.saveDetected(req));
  }

  @DeleteMapping("/{id}")
  @Operation(summary = "Delete a subnet definition")
  public ResponseEntity<Void> delete(@PathVariable Long id) {
    subnetService.delete(id);
    return ResponseEntity.noContent().build();
  }

  @GetMapping("/detect")
  @Operation(summary = "Auto-detect subnets from a capture file")
  public ResponseEntity<List<SubnetDefinitionDto>> detect(@RequestParam UUID fileId) {
    return ResponseEntity.ok(subnetService.detectFromFile(fileId));
  }

  @GetMapping("/detect/network")
  @Operation(summary = "Auto-detect subnets across a monitored network")
  public ResponseEntity<List<SubnetDefinitionDto>> detectFromNetwork(@RequestParam UUID networkId) {
    return ResponseEntity.ok(subnetService.detectFromNetwork(networkId));
  }

  @PostMapping("/{id}/suggest-label")
  @Operation(
      summary = "Suggest a label + description for a subnet with AI",
      description =
          "Collects the subnet's member nodes across recent snapshots and asks the LLM to suggest a "
              + "concise label naming the subnet plus a description of its purpose and any anomalies. "
              + "The result is not persisted — the analyst reviews it in the edit form and saves it "
              + "onto the subnet's own label/description. Optionally scope to a network via networkId.")
  @ApiResponses({
    @ApiResponse(responseCode = "200", description = "Suggested label + description"),
    @ApiResponse(responseCode = "422", description = "No member nodes observed — insufficient evidence")
  })
  public ResponseEntity<SubnetLabelSuggestionDto> suggestLabel(
      @PathVariable Long id,
      @RequestParam(required = false) UUID networkId,
      @RequestParam(required = false) UUID fileId) {
    return ResponseEntity.ok(subnetLabelSuggestionService.suggest(id, networkId, fileId));
  }

  @GetMapping("/{id}/history")
  @Operation(
      summary = "Per-snapshot composition history for a subnet",
      description =
          "For each snapshot of the given network where the subnet had members, returns the member "
              + "count and dominant device types + protocols — the basis for staleness detection.")
  public ResponseEntity<List<SubnetStalenessService.CompositionHistoryEntry>> history(
      @PathVariable Long id, @RequestParam UUID networkId) {
    return subnetService
        .find(id)
        .map(s -> ResponseEntity.ok(subnetStalenessService.history(s.getCidr(), networkId)))
        .orElseThrow(
            () ->
                new com.tracepcap.common.exception.ResourceNotFoundException(
                    "Subnet not found: " + id));
  }

  @PostMapping("/{id}/dismiss-staleness")
  @Operation(summary = "Mark a stale subnet label as still correct and re-baseline its composition")
  public ResponseEntity<SubnetDefinitionDto> dismissSubnetStaleness(
      @PathVariable Long id, @RequestParam(required = false) UUID networkId) {
    return ResponseEntity.ok(subnetService.dismissStaleness(id, networkId));
  }
}
