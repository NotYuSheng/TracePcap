package com.tracepcap.common.net;

/**
 * A resolved answer to "is this address inside our network" (#733).
 *
 * <p>Resolved, not resolvable: an implementation holds whatever operator configuration it needs
 * already loaded, so classifying a thousand addresses is a thousand comparisons rather than a
 * thousand queries. Obtain one from {@link LocalityPolicy} at the top of a batch and reuse it.
 *
 * <p>{@link #RFC_ONLY} is the bare heuristic, for callers with no operator context.
 */
@FunctionalInterface
public interface LocalityRules {

  /** The RFC ranges alone, ignoring any operator configuration. */
  LocalityRules RFC_ONLY = IpLocality::isLocal;

  boolean isLocal(String ip);

  /** The narrow slice of CIDR matching these rules need, so the kernel stays dependency-free. */
  @FunctionalInterface
  interface CidrSet {
    boolean contains(String ip);

    default boolean isEmpty() {
      return false;
    }
  }
}
