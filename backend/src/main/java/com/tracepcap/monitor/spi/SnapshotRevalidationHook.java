package com.tracepcap.monitor.spi;

import java.util.UUID;

/**
 * Port owned by monitor's change detection (#512 slice 3): a hook run after change detection for a
 * network's latest snapshot, so feature modules can re-validate their own baselines against it.
 * All implementations are list-injected and invoked in turn; implementors must degrade gracefully
 * rather than fail change detection.
 *
 * <p>Implemented today by {@code subnets} (subnet-definition composition staleness). The dependency
 * points subnets → monitor, keeping the modules acyclic.
 */
public interface SnapshotRevalidationHook {

  /** Re-validates this implementor's baselines against the given network's latest snapshot. */
  void revalidate(UUID networkId);
}
