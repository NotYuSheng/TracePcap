package com.tracepcap.notes.controller;

import com.tracepcap.notes.dto.EntityHistoryEntry;
import com.tracepcap.notes.dto.EntityNoteDto;
import com.tracepcap.notes.dto.UpsertNoteRequest;
import com.tracepcap.notes.service.EntityNoteService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/entity-notes")
@RequiredArgsConstructor
@Tag(name = "Entity Notes", description = "User notes attached to network entities, with history")
public class EntityNoteController {

  private final EntityNoteService service;

  @GetMapping
  @Operation(summary = "Get the note for an entity")
  public ResponseEntity<EntityNoteDto> getNote(
      @RequestParam String entityType,
      @RequestParam String entityKey) {
    return service
        .getNote(entityType, entityKey)
        .map(ResponseEntity::ok)
        .orElse(ResponseEntity.noContent().build());
  }

  @PutMapping
  @Operation(summary = "Create or update an entity's note")
  public ResponseEntity<EntityNoteDto> upsert(@RequestBody UpsertNoteRequest req) {
    if (req.getEntityType() == null || req.getEntityType().isBlank()) {
      return ResponseEntity.badRequest().build();
    }
    if (req.getEntityKey() == null || req.getEntityKey().isBlank()) {
      return ResponseEntity.badRequest().build();
    }
    if (req.getNote() == null) {
      req.setNote("");
    }
    return ResponseEntity.ok(service.upsert(req));
  }

  @DeleteMapping
  @Operation(summary = "Delete an entity's note")
  public ResponseEntity<Void> delete(
      @RequestParam String entityType,
      @RequestParam String entityKey) {
    service.delete(entityType, entityKey);
    return ResponseEntity.noContent().build();
  }

  @GetMapping("/history")
  @Operation(summary = "Get the change history for an entity's note")
  public List<EntityHistoryEntry> getHistory(
      @RequestParam String entityType,
      @RequestParam String entityKey) {
    return service.getHistory(entityType, entityKey);
  }
}
