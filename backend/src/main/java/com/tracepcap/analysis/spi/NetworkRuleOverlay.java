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

  /**
   * Names of the network's enabled rules that matched each of its snapshots' captures, batched.
   * Reads stored results only: snapshots are checked against the network's rules when they join and
   * when the rules change. Files with no matches are absent.
   */
  Map<UUID, Set<String>> matchedNamesByFile(UUID networkId, Collection<UUID> fileIds);

  /**
   * A conversation filter as seen in a network: a custom-signature filter also matches the
   * network's own rules (by conversation id), and the global rules it suppresses no longer match
   * (#925 phases 3 and 4). Unchanged with no network or no custom-signature filter. The one
   * place this rule lives, so every view that filters by rule agrees.
   */
  default com.tracepcap.analysis.dto.ConversationFilterParams scopeFilter(
      UUID networkId, UUID fileId, com.tracepcap.analysis.dto.ConversationFilterParams params) {
    if (networkId == null || params == null || params.getCustomSignatures() == null
        || params.getCustomSignatures().isEmpty()) {
      return params;
    }
    Set<String> suppressed = suppressedNames(networkId);
    List<String> wanted = params.getCustomSignatures().stream().filter(n -> !suppressed.contains(n)).toList();
    return params.toBuilder()
        // "" is no rule's name (names can't be blank), so it matches nothing by name.
        .customSignatures(wanted.isEmpty() ? List.of("") : wanted)
        .customSignatureMatchIds(conversationsMatching(networkId, fileId, params.getCustomSignatures()))
        .build();
  }
}
