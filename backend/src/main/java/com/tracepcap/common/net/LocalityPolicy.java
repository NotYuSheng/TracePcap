package com.tracepcap.common.net;

/**
 * Port for the operator's address configuration (#733).
 *
 * <p>Custom private ranges were honoured by exactly one backend service. An operator could mark a
 * range internal, see it respected in the monitor's change detection, and see it ignored by the
 * subnet view, the story narrative and the intelligence clustering — three screens disagreeing
 * with a fourth about the same host.
 *
 * <p>The port lives here rather than in the module that owns the ranges so that every consumer can
 * depend on it without depending on that module, and without a cycle. The implementation is
 * supplied at runtime, in the same shape as {@code analysis.spi}.
 */
public interface LocalityPolicy {

  /**
   * The current rules, resolved once. Callers classifying more than one address should hold the
   * result for the batch rather than calling this per address.
   */
  LocalityRules currentRules();

  /**
   * The current rules, plus extra CIDRs treated as internal — the monitor's per-snapshot subnet
   * definitions, which apply to one snapshot only.
   *
   * <p>An overload rather than a decorator on {@link LocalityRules}, because precedence cannot be
   * expressed by combining booleans after the fact: an operator override declaring a range PUBLIC
   * must not be flipped back by an extra CIDR, and once the rules have answered {@code false}
   * there is no way to tell that case apart from "the heuristic said no". Only the implementation
   * knows which answer came from an override.
   */
  LocalityRules currentRules(LocalityRules.CidrSet additionalPrivate);
}
