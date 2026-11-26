package com.tracepcap.analysis.spi;

import java.util.Optional;

/**
 * What the active IDS ruleset says about one rule, by its id (sid). ET Open tags most malware rules
 * with {@code metadata: ... malware_family <Name>}; that tag, not a guess from the rule's message, is
 * what names a malware family.
 */
public interface IdsRuleMetadata {

  /**
   * @param hasMetadata the rule carries a {@code metadata:} keyword at all (every ET rule does)
   * @param malwareFamily the {@code malware_family} tag, underscores as spaces ("Lumma Stealer"); null
   *     when the rule names none
   */
  record RuleInfo(boolean hasMetadata, String malwareFamily) {}

  /** The rule, or empty when it isn't in the active ruleset (a custom or since-removed rule). */
  Optional<RuleInfo> rule(long sid);

  /** No ruleset known: every lookup is empty, so callers fall back to their own reading. */
  IdsRuleMetadata NONE = sid -> Optional.empty();
}
