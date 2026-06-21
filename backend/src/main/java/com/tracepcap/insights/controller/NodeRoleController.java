package com.tracepcap.insights.controller;

import com.tracepcap.insights.dto.NodeRoleDto;
import com.tracepcap.insights.dto.UpsertNodeRoleRequest;
import com.tracepcap.insights.service.InsufficientEvidenceException;
import com.tracepcap.insights.service.NodeRoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/node-roles")
@RequiredArgsConstructor
@Tag(name = "Node Roles", description = "User-assigned roles for network entities (hosts/subnets)")
public class NodeRoleController {

  private final NodeRoleService service;

  @GetMapping
  @Operation(summary = "Get the role assigned to an entity")
  public ResponseEntity<NodeRoleDto> getRole(
      @RequestParam String entityType,
      @RequestParam String entityKey) {
    return service.getRole(entityType, entityKey)
        .map(ResponseEntity::ok)
        .orElse(ResponseEntity.noContent().build());
  }

  @PutMapping
  @Operation(summary = "Create or update an entity's role")
  public ResponseEntity<NodeRoleDto> upsert(@RequestBody UpsertNodeRoleRequest req) {
    if (req.getEntityType() == null || req.getEntityType().isBlank()) {
      return ResponseEntity.badRequest().build();
    }
    if (req.getEntityKey() == null || req.getEntityKey().isBlank()) {
      return ResponseEntity.badRequest().build();
    }
    return ResponseEntity.ok(service.upsert(req));
  }

  @DeleteMapping
  @Operation(summary = "Remove an entity's role")
  public ResponseEntity<Void> delete(
      @RequestParam String entityType,
      @RequestParam String entityKey) {
    service.delete(entityType, entityKey);
    return ResponseEntity.noContent().build();
  }

  @PostMapping("/suggest")
  @Operation(summary = "Suggest a role for an entity based on observed traffic")
  public ResponseEntity<?> suggest(
      @RequestParam String entityType,
      @RequestParam String entityKey,
      @RequestParam UUID fileId) {
    try {
      return ResponseEntity.ok(service.suggestRole(entityType, entityKey, fileId));
    } catch (InsufficientEvidenceException e) {
      return ResponseEntity.unprocessableEntity().body(Map.of("error", e.getMessage()));
    }
  }
}
