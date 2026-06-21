package com.tracepcap.insights.controller;

import com.tracepcap.insights.dto.CreateAnnotationRequest;
import com.tracepcap.insights.dto.NetworkAnnotationDto;
import com.tracepcap.insights.dto.UpdateAnnotationRequest;
import com.tracepcap.insights.service.NetworkAnnotationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/monitor/networks/{networkId}/annotations")
@RequiredArgsConstructor
@Tag(name = "Network Annotations", description = "Free-text annotations on a monitored network")
public class NetworkAnnotationController {

  private final NetworkAnnotationService service;

  @GetMapping
  @Operation(summary = "List annotations for a network")
  public List<NetworkAnnotationDto> list(@PathVariable UUID networkId) {
    return service.listAnnotations(networkId);
  }

  @PostMapping
  @Operation(summary = "Create an annotation")
  public ResponseEntity<NetworkAnnotationDto> create(
      @PathVariable UUID networkId,
      @RequestBody CreateAnnotationRequest req) {
    if (req.getBody() == null || req.getBody().isBlank()) {
      return ResponseEntity.badRequest().build();
    }
    return ResponseEntity.status(HttpStatus.CREATED).body(service.createAnnotation(networkId, req));
  }

  @PatchMapping("/{annotationId}")
  @Operation(summary = "Update an annotation's body")
  public ResponseEntity<NetworkAnnotationDto> update(
      @PathVariable UUID networkId,
      @PathVariable UUID annotationId,
      @RequestBody UpdateAnnotationRequest req) {
    if (req.getBody() == null || req.getBody().isBlank()) return ResponseEntity.badRequest().build();
    return ResponseEntity.ok(service.updateAnnotation(networkId, annotationId, req.getBody()));
  }

  @DeleteMapping("/{annotationId}")
  @Operation(summary = "Delete an annotation")
  public ResponseEntity<Void> delete(
      @PathVariable UUID networkId,
      @PathVariable UUID annotationId) {
    service.deleteAnnotation(networkId, annotationId);
    return ResponseEntity.noContent().build();
  }
}
