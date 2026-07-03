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
  @Operation(summary = "Get the role assigned to an entity in a file")
  public ResponseEntity<NodeRoleDto> getRole(
      @RequestParam UUID fileId, @RequestParam String entityType, @RequestParam String entityKey) {
    return service
        .getRole(fileId, entityType, entityKey)
        .map(ResponseEntity::ok)
        .orElse(ResponseEntity.noContent().build());
  }

  @PutMapping
  @Operation(summary = "Create or update an entity's role in a file")
  public ResponseEntity<NodeRoleDto> upsert(@RequestBody UpsertNodeRoleRequest req) {
    if (req.getFileId() == null) {
      return ResponseEntity.badRequest().build();
    }
    if (req.getEntityType() == null || req.getEntityType().isBlank()) {
      return ResponseEntity.badRequest().build();
    }
    if (req.getEntityKey() == null || req.getEntityKey().isBlank()) {
      return ResponseEntity.badRequest().build();
    }
    return ResponseEntity.ok(service.upsert(req));
  }

  @DeleteMapping
  @Operation(summary = "Remove an entity's role in a file")
  public ResponseEntity<Void> delete(
      @RequestParam UUID fileId, @RequestParam String entityType, @RequestParam String entityKey) {
    service.delete(fileId, entityType, entityKey);
    return ResponseEntity.noContent().build();
  }

  @PostMapping("/dismiss-staleness")
  @Operation(
      summary = "Dismiss a stale-label warning",
      description =
          "Clears the staleness flag for a confirmed label and records the current file's node"
              + " properties as the new drift baseline.")
  public ResponseEntity<NodeRoleDto> dismissStaleness(
      @RequestParam UUID fileId, @RequestParam String entityType, @RequestParam String entityKey) {
    return service
        .dismissStaleness(fileId, entityType, entityKey)
        .map(ResponseEntity::ok)
        .orElse(ResponseEntity.noContent().build());
  }

  @PostMapping("/suggest")
  @Operation(summary = "Suggest a role for an entity based on observed traffic")
  public ResponseEntity<?> suggest(
      @RequestParam String entityType, @RequestParam String entityKey, @RequestParam UUID fileId) {
    try {
      return ResponseEntity.ok(service.suggestRole(entityType, entityKey, fileId));
    } catch (InsufficientEvidenceException e) {
      return ResponseEntity.unprocessableEntity().body(Map.of("error", e.getMessage()));
    }
  }

  @PostMapping("/suggest-preview")
  @Operation(
      summary = "Preview an AI role suggestion without persisting",
      description =
          "Generates a fresh label/description from the file's traffic to pre-fill the update-label"
              + " editor — used to re-classify a drifted label without overwriting the confirmed one.")
  public ResponseEntity<?> suggestPreview(
      @RequestParam String entityType, @RequestParam String entityKey, @RequestParam UUID fileId) {
    try {
      return ResponseEntity.ok(service.suggestRolePreview(entityType, entityKey, fileId));
    } catch (InsufficientEvidenceException e) {
      return ResponseEntity.unprocessableEntity().body(Map.of("error", e.getMessage()));
    }
  }
}
