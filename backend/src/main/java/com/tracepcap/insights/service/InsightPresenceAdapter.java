package com.tracepcap.insights.service;

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
}
