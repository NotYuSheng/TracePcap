package com.lanturn.subnets.controller;

import com.lanturn.subnets.dto.SubnetDefinitionDto;
import com.lanturn.subnets.dto.UpsertSubnetRequest;
import com.lanturn.subnets.service.SubnetService;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/subnets")
@RequiredArgsConstructor
public class SubnetController {

  private final SubnetService subnetService;

  @GetMapping
  public ResponseEntity<List<SubnetDefinitionDto>> list() {
    return ResponseEntity.ok(subnetService.list());
  }

  @PostMapping
  public ResponseEntity<SubnetDefinitionDto> upsert(@RequestBody UpsertSubnetRequest req) {
    return ResponseEntity.ok(subnetService.upsert(req));
  }

  @PostMapping("/detected")
  public ResponseEntity<SubnetDefinitionDto> saveDetected(@RequestBody UpsertSubnetRequest req) {
    return ResponseEntity.ok(subnetService.saveDetected(req));
  }

  @DeleteMapping("/{id}")
  public ResponseEntity<Void> delete(@PathVariable Long id) {
    subnetService.delete(id);
    return ResponseEntity.noContent().build();
  }

  @GetMapping("/detect")
  public ResponseEntity<List<SubnetDefinitionDto>> detect(@RequestParam UUID fileId) {
    return ResponseEntity.ok(subnetService.detectFromFile(fileId));
  }

  @GetMapping("/detect/network")
  public ResponseEntity<List<SubnetDefinitionDto>> detectFromNetwork(@RequestParam UUID networkId) {
    return ResponseEntity.ok(subnetService.detectFromNetwork(networkId));
  }
}
