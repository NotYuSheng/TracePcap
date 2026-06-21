package com.tracepcap.insights.controller;

import com.tracepcap.insights.dto.CreateExternalEventRequest;
import com.tracepcap.insights.dto.NetworkExternalEventDto;
import com.tracepcap.insights.service.NetworkExternalEventService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/monitor/networks/{networkId}/external-events")
@RequiredArgsConstructor
@Tag(
    name = "Network External Events",
    description = "User-recorded external events correlated with a monitored network")
public class NetworkExternalEventController {

  private final NetworkExternalEventService service;

  @GetMapping
  @Operation(summary = "List external events for a network")
  public List<NetworkExternalEventDto> list(@PathVariable UUID networkId) {
    return service.listEvents(networkId);
  }

  @PostMapping
  @Operation(summary = "Create an external event")
  public ResponseEntity<NetworkExternalEventDto> create(
      @PathVariable UUID networkId,
      @RequestBody CreateExternalEventRequest req) {
    if (req.getTitle() == null || req.getTitle().isBlank()) {
      return ResponseEntity.badRequest().build();
    }
    if (req.getEventTime() == null) {
      return ResponseEntity.badRequest().build();
    }
    return ResponseEntity.status(HttpStatus.CREATED).body(service.createEvent(networkId, req));
  }

  @DeleteMapping("/{eventId}")
  @Operation(summary = "Delete an external event")
  public ResponseEntity<Void> delete(
      @PathVariable UUID networkId,
      @PathVariable UUID eventId) {
    service.deleteEvent(networkId, eventId);
    return ResponseEntity.noContent().build();
  }
}
