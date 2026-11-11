package com.tracepcap.analysis.spi;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * The detection rules in effect for a capture, by name (#925): enabled global rules (minus those a
 * network suppresses), the capture's own, and the network's own when a network is the context.
 * Lets readers outside the {@code signatures} module, such as Story, describe a match. Implemented
 * by {@code signatures}.
 */
public interface DetectionRuleCatalog {

  /** A rule as a reader sees it. {@code scope} is "global", "capture", or the network's name. */
  record RuleSummary(String name, String severity, String description, String scope) {}

  /** Rule name → summary, for the rules in effect on {@code fileId} viewed in {@code networkId} (may be null). */
  Map<String, RuleSummary> rulesInEffect(UUID fileId, UUID networkId);

  /** The network's name, if it exists. */
  Optional<String> networkName(UUID networkId);
}
