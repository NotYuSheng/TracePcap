package com.tracepcap.networkmap;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** A capture's network map edits (#649): where the analyst moved devices. */
@RestController
@RequestMapping("/files")
@RequiredArgsConstructor
@Tag(name = "Network Map", description = "The analyst's edits to a capture's network map")
public class NetworkMapEditsController {

  private final NetworkMapEditsService service;

  @GetMapping("/{fileId}/network-map-edits")
  @Operation(
      summary = "A capture's network map edits",
      description = "Which group each moved device was put in. Empty when the map was never edited.")
  public NetworkMapEditsResponse getNetworkMapEdits(@PathVariable UUID fileId) {
    return service.get(fileId);
  }

  @PutMapping("/{fileId}/network-map-edits")
  @Operation(
      summary = "Save a capture's network map edits",
      description = "Replaces the edits. Needs the NETWORK_MAP permission. Audited.")
  public NetworkMapEditsResponse saveNetworkMapEdits(@PathVariable UUID fileId, @Valid @RequestBody NetworkMapEdits edits) {
    return service.save(fileId, edits);
  }

  @DeleteMapping("/{fileId}/network-map-edits")
  @Operation(
      summary = "Reset a capture's network map to automatic",
      description = "Drops every edit. Needs the NETWORK_MAP permission. Audited.")
  public ResponseEntity<Void> resetNetworkMapEdits(@PathVariable UUID fileId) {
    service.reset(fileId);
    return ResponseEntity.noContent().build();
  }
}
