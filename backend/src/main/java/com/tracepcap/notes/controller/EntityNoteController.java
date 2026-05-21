package com.tracepcap.notes.controller;

import com.tracepcap.notes.dto.EntityHistoryEntry;
import com.tracepcap.notes.dto.EntityNoteDto;
import com.tracepcap.notes.dto.UpsertNoteRequest;
import com.tracepcap.notes.service.EntityNoteService;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/entity-notes")
@RequiredArgsConstructor
public class EntityNoteController {

  private final EntityNoteService service;

  @GetMapping
  public ResponseEntity<EntityNoteDto> getNote(
      @RequestParam String entityType,
      @RequestParam String entityKey) {
    return service
        .getNote(entityType, entityKey)
        .map(ResponseEntity::ok)
        .orElse(ResponseEntity.noContent().build());
  }

  @PutMapping
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
  public ResponseEntity<Void> delete(
      @RequestParam String entityType,
      @RequestParam String entityKey) {
    service.delete(entityType, entityKey);
    return ResponseEntity.noContent().build();
  }

  @GetMapping("/history")
  public List<EntityHistoryEntry> getHistory(
      @RequestParam String entityType,
      @RequestParam String entityKey) {
    return service.getHistory(entityType, entityKey);
  }
}
