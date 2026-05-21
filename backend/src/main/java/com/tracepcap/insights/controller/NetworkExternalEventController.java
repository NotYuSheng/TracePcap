package com.lanturn.insights.controller;

import com.lanturn.insights.dto.CreateExternalEventRequest;
import com.lanturn.insights.dto.NetworkExternalEventDto;
import com.lanturn.insights.service.NetworkExternalEventService;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/monitor/networks/{networkId}/external-events")
@RequiredArgsConstructor
public class NetworkExternalEventController {

  private final NetworkExternalEventService service;

  @GetMapping
  public List<NetworkExternalEventDto> list(@PathVariable UUID networkId) {
    return service.listEvents(networkId);
  }

  @PostMapping
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
  public ResponseEntity<Void> delete(
      @PathVariable UUID networkId,
      @PathVariable UUID eventId) {
    service.deleteEvent(networkId, eventId);
    return ResponseEntity.noContent().build();
  }
}
