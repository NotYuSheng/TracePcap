package com.tracepcap.monitor.controller;

import com.tracepcap.monitor.dto.AddSnapshotRequest;
import com.tracepcap.monitor.dto.NetworkSnapshotDto;
import com.tracepcap.monitor.dto.PatchSnapshotRequest;
import com.tracepcap.monitor.service.SnapshotService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/monitor/networks/{networkId}/snapshots")
@RequiredArgsConstructor
@Tag(name = "Monitor Snapshots", description = "Capture snapshots attached to a monitored network")
public class NetworkSnapshotController {

  private final SnapshotService snapshotService;

  @GetMapping
  @Operation(summary = "List snapshots for a network")
  public List<NetworkSnapshotDto> listSnapshots(@PathVariable UUID networkId) {
    return snapshotService.listSnapshots(networkId);
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  @Operation(summary = "Add a snapshot to a network")
  public NetworkSnapshotDto addSnapshot(
      @PathVariable UUID networkId, @Valid @RequestBody AddSnapshotRequest request) {
    return snapshotService.addSnapshot(networkId, request.getFileId(), request.getSubnetOverrides());
  }

  @PatchMapping("/{snapshotId}")
  @Operation(summary = "Update a snapshot's metadata")
  public NetworkSnapshotDto patchSnapshot(
      @PathVariable UUID networkId,
      @PathVariable UUID snapshotId,
      @Valid @RequestBody PatchSnapshotRequest request) {
    return snapshotService.patchSnapshot(networkId, snapshotId, request);
  }

  @DeleteMapping("/{snapshotId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  @Operation(summary = "Remove a snapshot from a network")
  public void removeSnapshot(@PathVariable UUID networkId, @PathVariable UUID snapshotId) {
    snapshotService.removeSnapshot(networkId, snapshotId);
  }
}
