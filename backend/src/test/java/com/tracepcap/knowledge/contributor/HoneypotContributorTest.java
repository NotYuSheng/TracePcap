package com.tracepcap.knowledge.contributor;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.ConversationLookup.HostPair;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class HoneypotContributorTest {

  private static final Map<String, String> DECOYS =
      Map.of("198.51.100.22", "Cowrie honeypot", "198.51.100.45", "Dionaea honeypot");

  @Test
  void whoOpenedConversationsToADecoyReachedIt() {
    var out = HoneypotContributor.contacts(List.of(
        // stored either way round: the opener counts, wherever it is in the pair
        new HostPair("198.51.100.101", "198.51.100.22", 6, 6, 0),
        new HostPair("198.51.100.45", "198.51.100.101", 3, 0, 3)), DECOYS);
    assertThat(out).containsOnlyKeys("198.51.100.101");
    assertThat(out.get("198.51.100.101").conversations).isEqualTo(9);
    assertThat(out.get("198.51.100.101").reached)
        .containsOnlyKeys("198.51.100.22", "198.51.100.45");
  }

  @Test
  void aDecoyReachingOutAndDecoysProbingEachOtherDontCount() {
    var out = HoneypotContributor.contacts(List.of(
        new HostPair("198.51.100.22", "198.51.100.200", 2, 2, 0),
        new HostPair("198.51.100.22", "198.51.100.45", 4, 2, 2),
        // a UDP or mid-stream conversation: nobody known to have opened it
        new HostPair("198.51.100.150", "198.51.100.22", 5, 0, 0)), DECOYS);
    assertThat(out).isEmpty();
  }
}
