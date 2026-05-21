package com.lanturn.monitor.controller;

import com.lanturn.monitor.dto.AddSnapshotRequest;
import com.lanturn.monitor.dto.NetworkSnapshotDto;
import com.lanturn.monitor.dto.PatchSnapshotRequest;
import com.lanturn.monitor.service.SnapshotService;
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
    return snapshotService.addSnapshot(networkId, request.getFileId());
  }

  @PatchMapping("/{snapshotId}")
  public NetworkSnapshotDto patchSnapshot(
      @PathVariable UUID networkId,
      @PathVariable UUID snapshotId,
      @RequestBody PatchSnapshotRequest request) {
    return snapshotService.patchSnapshot(networkId, snapshotId, request);
  }

  @DeleteMapping("/{snapshotId}")
  @ResponseStatus(HttpStatus.NO_CONTENT)
  public void removeSnapshot(@PathVariable UUID networkId, @PathVariable UUID snapshotId) {
    snapshotService.removeSnapshot(networkId, snapshotId);
  }
}
