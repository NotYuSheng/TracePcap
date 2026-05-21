package com.lanturn.insights.controller;

import com.lanturn.insights.dto.NodeRoleDto;
import com.lanturn.insights.dto.UpsertNodeRoleRequest;
import com.lanturn.insights.service.InsufficientEvidenceException;
import com.lanturn.insights.service.NodeRoleService;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/node-roles")
@RequiredArgsConstructor
public class NodeRoleController {

  private final NodeRoleService service;

  @GetMapping
  public ResponseEntity<NodeRoleDto> getRole(
      @RequestParam String entityType,
      @RequestParam String entityKey) {
    return service.getRole(entityType, entityKey)
        .map(ResponseEntity::ok)
        .orElse(ResponseEntity.noContent().build());
  }

  @PutMapping
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
  public ResponseEntity<Void> delete(
      @RequestParam String entityType,
      @RequestParam String entityKey) {
    service.delete(entityType, entityKey);
    return ResponseEntity.noContent().build();
  }

  @PostMapping("/suggest")
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
