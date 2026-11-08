package com.tracepcap.monitor.controller;

import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Which monitored networks a capture is a snapshot of (#925 phase 3: the network-context picker). */
@RestController
@RequestMapping("/files/{fileId}/networks")
@RequiredArgsConstructor
@Tag(name = "Monitor Networks", description = "Manage monitored networks")
public class FileNetworksController {

  private final NetworkSnapshotRepository snapshotRepository;

  /** A network, by id and name. */
  public record NetworkRef(UUID id, String name) {}

  @GetMapping
  @Operation(summary = "The networks this capture is a snapshot of")
  @Transactional(readOnly = true)
  public List<NetworkRef> list(@PathVariable UUID fileId) {
    return snapshotRepository.findByFileId(fileId).stream()
        .map(s -> new NetworkRef(s.getNetwork().getId(), s.getNetwork().getName()))
        .distinct()
        .toList();
  }
}
