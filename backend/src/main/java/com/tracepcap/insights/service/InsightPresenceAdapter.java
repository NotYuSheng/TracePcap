package com.tracepcap.insights.service;

import java.util.Set;
import java.util.HashSet;
import java.util.Collection;
import com.tracepcap.insights.repository.NetworkInsightRepository;
import com.tracepcap.insights.repository.SnapshotInsightRepository;
import com.tracepcap.monitor.spi.InsightPresence;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Implements monitor's {@link InsightPresence} port (#512 slice 3), so monitor DTO mapping can ask
 * "does this network/snapshot have insights?" without reaching into this module's repositories.
 */
@Component
@RequiredArgsConstructor
public class InsightPresenceAdapter implements InsightPresence {

  private final NetworkInsightRepository networkInsightRepository;
  private final SnapshotInsightRepository snapshotInsightRepository;

  @Override
  public boolean networkHasInsights(UUID networkId) {
    return networkInsightRepository.existsByNetworkId(networkId);
  }

  @Override
  public boolean snapshotHasInsights(UUID snapshotId) {
    return snapshotInsightRepository.existsBySnapshotId(snapshotId);
  }

  @Override
  public Set<UUID> networksWithInsights(Collection<UUID> networkIds) {
    // An empty IN () is invalid SQL on some databases, and there's nothing to ask anyway.
    if (networkIds.isEmpty()) return Set.of();
    return new HashSet<>(networkInsightRepository.findNetworkIdsWithInsights(networkIds));
  }

  @Override
  public Set<UUID> snapshotsWithInsights(Collection<UUID> snapshotIds) {
    if (snapshotIds.isEmpty()) return Set.of();
    return new HashSet<>(snapshotInsightRepository.findSnapshotIdsWithInsights(snapshotIds));
  }
}
