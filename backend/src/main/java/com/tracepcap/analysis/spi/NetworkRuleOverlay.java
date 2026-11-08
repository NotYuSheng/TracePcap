package com.tracepcap.analysis.spi;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Matches of a network's own detection rules on one capture (#925 phase 3). Unlike global and
 * capture rules, these depend on which network the capture is being viewed in, so they aren't
 * stored on the conversation: read endpoints add them when a network is the context. Only the
 * network's enabled rules count. Implemented by the {@code signatures} module.
 */
public interface NetworkRuleOverlay {

  /** Conversation id → names of the network's enabled rules that matched it. */
  Map<UUID, List<String>> labels(UUID networkId, UUID fileId);

  /** Conversations in the capture matched by any of the network's enabled rules called {@code names}. */
  Set<UUID> conversationsMatching(UUID networkId, UUID fileId, Collection<String> names);

  /**
   * Names of the global rules this network has switched off in its views (#925 phase 4): their
   * stored matches are hidden when a capture is viewed in the network.
   */
  Set<String> suppressedNames(UUID networkId);
}
