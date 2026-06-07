package com.tracepcap.monitor.controller;

import com.tracepcap.monitor.dto.AddSnapshotRequest;
import com.tracepcap.monitor.dto.NetworkSnapshotDto;
import com.tracepcap.monitor.dto.PatchSnapshotRequest;
import com.tracepcap.monitor.service.SnapshotService;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/monitor/networks/{networkId}/snapshots")
@RequiredArgsConstructor
public class NetworkSnapshotController {

  private final SnapshotService snapshotService;

  @GetMapping
  public List<NetworkSnapshotDto> listSnapshots(@PathVariable UUID networkId) {
    return snapshotService.listSnapshots(networkId);
  }

  @PostMapping
  @ResponseStatus(HttpStatus.CREATED)
  public NetworkSnapshotDto addSnapshot(
      @PathVariable UUID networkId, @Valid @RequestBody AddSnapshotRequest request) {
    return snapshotService.addSnapshot(networkId, request.getFileId(), request.getSubnetOverrides());
  }

  @PatchMapping("/{snapshotId}")
  public NetworkSnapshotDto patchSnapshot(
      @PathVariable UUID networkId,
      @PathVariable UUID snapshotId,
      @Valid @RequestBody PatchSnapshotRequest request) {
    return snapshotService.patchSnapshot(networkId, snapshotId, request);
  }

  @DeleteMapping("/{snapshotId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void removeSnapshot(@PathVariable UUID networkId, @PathVariable UUID snapshotId) {
    snapshotService.removeSnapshot(networkId, snapshotId);
  }
}
