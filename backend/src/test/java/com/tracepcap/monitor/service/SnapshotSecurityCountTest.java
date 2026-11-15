package com.tracepcap.monitor.service;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Set;
import org.junit.jupiter.api.Test;

/** The snapshot's security-signal count as seen in its network (#925). */
class SnapshotSecurityCountTest {

  @Test
  void unchangedWithNoSuppressionsOrNetworkRules() {
    assertThat(SnapshotService.adjustedCount(5, Set.of("a", "b"), Set.of(), Set.of())).isEqualTo(5);
  }

  @Test
  void suppressedGlobalRulesDropOut() {
    // 5 signals: 2 stored rule names (a, b) plus 3 others; the network switches off "a".
    assertThat(SnapshotService.adjustedCount(5, Set.of("a", "b"), Set.of("a", "zz"), Set.of())).isEqualTo(4);
  }

  @Test
  void networkRuleMatchesAddOnce() {
    // "b" is already counted as a stored name; "net-dns" is new.
    assertThat(SnapshotService.adjustedCount(5, Set.of("a", "b"), Set.of(), Set.of("b", "net-dns"))).isEqualTo(6);
  }

  @Test
  void aNetworkRuleNamedLikeASuppressedGlobalStillCounts() {
    assertThat(SnapshotService.adjustedCount(2, Set.of("a"), Set.of("a"), Set.of("a"))).isEqualTo(2);
  }
}
