package com.tracepcap.monitor.spi;

import java.util.List;
import java.util.UUID;

/**
 * Port owned by monitor's change detection (#512 slice 3): carries node-role labels forward from
 * one snapshot's file to the next and reports which labels have gone stale. Implemented by the
 * {@code insights} module — the dependency points insights → monitor, mirroring the
 * {@code analysis.spi} pattern from #416, so the two modules stay acyclic.
 */
public interface LabelStalenessCheck {

  /** One carried-forward label whose observed properties drifted from the previous snapshot. */
  record Drift(String entityType, String entityKey, String roleLabel, List<String> changedFields) {}

  /**
   * Carries labels forward from {@code prevFileId} (may be null for a first snapshot) to
   * {@code newFileId} and returns the labels whose underlying evidence has drifted.
   */
  List<Drift> carryForwardAndValidate(UUID prevFileId, UUID newFileId);
}
