package com.tracepcap.subnets.controller;

import com.tracepcap.subnets.dto.SubnetDefinitionDto;
import com.tracepcap.subnets.dto.UpsertSubnetRequest;
import com.tracepcap.subnets.service.SubnetService;
import io.swagger.v3.oas.annotations.Operation;
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
}
