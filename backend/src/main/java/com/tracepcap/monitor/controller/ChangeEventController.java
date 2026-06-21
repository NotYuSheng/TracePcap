package com.tracepcap.monitor.controller;

import com.tracepcap.monitor.dto.ChangeEventDto;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity.ChangeType;
import com.tracepcap.monitor.entity.NetworkChangeEventEntity.Severity;
import com.tracepcap.monitor.repository.NetworkChangeEventRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/monitor/networks/{networkId}/changes")
@RequiredArgsConstructor
@Tag(name = "Monitor Change Events", description = "Detected drift events for a monitored network")
public class ChangeEventController {

  private final NetworkChangeEventRepository changeEventRepository;

  @GetMapping
  @Operation(summary = "List change events, optionally filtered by type and severity")
  public List<ChangeEventDto> listChanges(
      @PathVariable UUID networkId,
      @RequestParam Optional<String> changeType,
      @RequestParam Optional<String> severity) {

    ChangeType ct =
        changeType.filter(s -> !s.isBlank()).map(s -> ChangeType.valueOf(s.toUpperCase())).orElse(null);
    Severity sv =
        severity.filter(s -> !s.isBlank()).map(s -> Severity.valueOf(s.toUpperCase())).orElse(null);

    return changeEventRepository.findFiltered(networkId, ct, sv).stream()
        .map(this::toDto)
        .collect(Collectors.toList());
  }

  @PatchMapping("/{eventId}")
  @Operation(summary = "Update a change event's reviewed flag or notes")
  public ResponseEntity<ChangeEventDto> patchEvent(
      @PathVariable UUID networkId,
      @PathVariable UUID eventId,
      @RequestBody Map<String, Object> body) {

    return changeEventRepository.findById(eventId)
        .filter(e -> e.getNetwork().getId().equals(networkId))
        .map(e -> {
          if (body.containsKey("reviewed")) {
            e.setReviewed(Boolean.TRUE.equals(body.get("reviewed")));
          }
          if (body.containsKey("notes")) {
            Object n = body.get("notes");
            e.setNotes(n instanceof String s && !s.isBlank() ? s : null);
          }
          return ResponseEntity.ok(toDto(changeEventRepository.save(e)));
        })
        .orElse(ResponseEntity.notFound().build());
  }

  private ChangeEventDto toDto(com.tracepcap.monitor.entity.NetworkChangeEventEntity e) {
    return ChangeEventDto.builder()
        .id(e.getId())
        .networkId(e.getNetwork().getId())
        .fromSnapshotId(e.getFromSnapshot() != null ? e.getFromSnapshot().getId() : null)
        .toSnapshotId(e.getToSnapshot().getId())
        .changeType(e.getChangeType().name())
        .entityType(e.getEntityType().name())
        .entityKey(e.getEntityKey())
        .oldValue(e.getOldValue())
        .newValue(e.getNewValue())
        .severity(e.getSeverity().name())
        .detectedAt(e.getDetectedAt())
        .reviewed(e.isReviewed())
        .notes(e.getNotes())
        .build();
  }
}
