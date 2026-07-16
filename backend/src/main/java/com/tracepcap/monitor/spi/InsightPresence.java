package com.tracepcap.monitor.spi;

import java.util.UUID;

/**
 * Port owned by monitor (#512 slice 3): whether AI insights exist for a network or snapshot, used
 * to populate the {@code hasInsights} flags on monitor DTOs without monitor reaching into the
 * {@code insights} module's repositories. Implemented by {@code insights}.
 */
public interface InsightPresence {

  boolean networkHasInsights(UUID networkId);

  boolean snapshotHasInsights(UUID snapshotId);
}
