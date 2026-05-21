package com.tracepcap.insights.controller;

import com.tracepcap.insights.dto.CreateAnnotationRequest;
import com.tracepcap.insights.dto.NetworkAnnotationDto;
import com.tracepcap.insights.dto.UpdateAnnotationRequest;
import com.tracepcap.insights.service.NetworkAnnotationService;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/monitor/networks/{networkId}/annotations")
@RequiredArgsConstructor
public class NetworkAnnotationController {

  private final NetworkAnnotationService service;

  @GetMapping
  public List<NetworkAnnotationDto> list(@PathVariable UUID networkId) {
    return service.listAnnotations(networkId);
  }

  @PostMapping
  public ResponseEntity<NetworkAnnotationDto> create(
      @PathVariable UUID networkId,
      @RequestBody CreateAnnotationRequest req) {
    if (req.getBody() == null || req.getBody().isBlank()) {
      return ResponseEntity.badRequest().build();
    }
    return ResponseEntity.status(HttpStatus.CREATED).body(service.createAnnotation(networkId, req));
  }

  @PatchMapping("/{annotationId}")
  public ResponseEntity<NetworkAnnotationDto> update(
      @PathVariable UUID networkId,
      @PathVariable UUID annotationId,
      @RequestBody UpdateAnnotationRequest req) {
    if (req.getBody() == null || req.getBody().isBlank()) return ResponseEntity.badRequest().build();
    return ResponseEntity.ok(service.updateAnnotation(networkId, annotationId, req.getBody()));
  }

  @DeleteMapping("/{annotationId}")
  public ResponseEntity<Void> delete(
      @PathVariable UUID networkId,
      @PathVariable UUID annotationId) {
    service.deleteAnnotation(networkId, annotationId);
    return ResponseEntity.noContent().build();
  }
}
