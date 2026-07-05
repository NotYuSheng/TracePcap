package com.tracepcap.monitor.service;

import com.tracepcap.monitor.entity.NetworkSnapshotEntity;
import com.tracepcap.monitor.entity.SnapshotSubnetOverrideEntity;
import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import com.tracepcap.monitor.repository.SnapshotSubnetOverrideRepository;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Carries subnet labels forward across snapshots, mirroring the node-role carry-forward in {@code
 * LabelStalenessService}. When a new snapshot is added, each subnet override on the previous snapshot
 * is copied onto the new one as an <b>inherited</b> override (unless the analyst has already set that
 * CIDR directly on the new snapshot, which takes precedence). Inherited rows are regenerated on each
 * transition so reorders/re-adds stay consistent.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SubnetOverrideCarryForwardService {

  private final SnapshotSubnetOverrideRepository overrideRepository;
  private final NetworkSnapshotRepository snapshotRepository;

  /**
   * Copy {@code prevSnapshotId}'s subnet overrides onto {@code newSnapshotId} as inherited rows.
   * Analyst-set (non-inherited) overrides already present on the new snapshot are left untouched and
   * win over a carried value for the same CIDR.
   */
  @Transactional
  public void carryForward(UUID prevSnapshotId, UUID newSnapshotId) {
    if (newSnapshotId == null) return;
    // Always clear carried rows so a reorder/re-add regenerates cleanly.
    overrideRepository.deleteBySnapshotIdAndInheritedTrue(newSnapshotId);
    if (prevSnapshotId == null) return;

    List<SnapshotSubnetOverrideEntity> prev = overrideRepository.findBySnapshotId(prevSnapshotId);
    if (prev.isEmpty()) return;

    NetworkSnapshotEntity newSnapshot = snapshotRepository.findById(newSnapshotId).orElse(null);
    if (newSnapshot == null) return;

    // CIDRs the analyst has labelled directly on the new snapshot — don't shadow them.
    Set<String> directCidrs =
        overrideRepository.findBySnapshotId(newSnapshotId).stream()
            .filter(o -> !o.isInherited())
            .map(SnapshotSubnetOverrideEntity::getCidr)
            .collect(Collectors.toSet());

    List<SnapshotSubnetOverrideEntity> toSave = new java.util.ArrayList<>();
    for (SnapshotSubnetOverrideEntity src : prev) {
      if (directCidrs.contains(src.getCidr())) continue;
      toSave.add(
          SnapshotSubnetOverrideEntity.builder()
              .snapshot(newSnapshot)
              .cidr(src.getCidr())
              .label(src.getLabel())
              .description(src.getDescription())
              .inherited(true)
              .build());
    }
    if (!toSave.isEmpty()) overrideRepository.saveAll(toSave);
  }
}
