package com.tracepcap.monitor.controller;

import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Which captures are snapshots of which monitored networks, all at once: the captures list shows
 * "Kept with <network>" on each one, and such a capture is never deleted by the analysis retention.
 */
@RestController
@RequestMapping("/network-memberships")
@RequiredArgsConstructor
@Tag(name = "Monitor Networks", description = "Manage monitored networks")
public class NetworkMembershipController {

  private final NetworkSnapshotRepository snapshotRepository;

  /** One capture in one network. */
  public record NetworkMembership(UUID fileId, UUID networkId, String networkName) {}

  @GetMapping
  @Operation(summary = "Every capture that is a snapshot of a monitored network, with the network")
  @Transactional(readOnly = true)
  public List<NetworkMembership> list() {
    return snapshotRepository.findAllMembershipsWithNames().stream()
        .map(r -> new NetworkMembership((UUID) r[0], (UUID) r[1], (String) r[2]))
        .distinct()
        .toList();
  }
}
