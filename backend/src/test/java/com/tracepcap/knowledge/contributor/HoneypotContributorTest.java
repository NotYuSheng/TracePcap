package com.tracepcap.knowledge.contributor;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.ConversationLookup.Opening;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class HoneypotContributorTest {

  private static final Map<String, String> DECOYS =
      Map.of("198.51.100.22", "Cowrie honeypot", "198.51.100.45", "Dionaea honeypot");

  @Test
  void whoOpenedConversationsToADecoyReachedIt() {
    var out = HoneypotContributor.contacts(List.of(
        new Opening("198.51.100.101", "198.51.100.22", 6),
        new Opening("198.51.100.101", "198.51.100.45", 3)), DECOYS);
    assertThat(out).containsOnlyKeys("198.51.100.101");
    assertThat(out.get("198.51.100.101").conversations).isEqualTo(9);
    assertThat(out.get("198.51.100.101").reached)
        .containsOnlyKeys("198.51.100.22", "198.51.100.45");
  }

  @Test
  void aDecoyReachingOutAndDecoysProbingEachOtherDontCount() {
    var out = HoneypotContributor.contacts(List.of(
        // the decoy opened these: the database returns them only as openings to their targets
        new Opening("198.51.100.22", "198.51.100.200", 2),
        new Opening("198.51.100.22", "198.51.100.45", 2),
        new Opening("198.51.100.45", "198.51.100.22", 2)), DECOYS);
    assertThat(out).isEmpty();
  }

  @Test
  void anAnalystsOwnLabelGetsTheRightArticle() {
    assertThat(HoneypotContributor.article("Cowrie honeypot")).isEqualTo("a Cowrie honeypot");
    assertThat(HoneypotContributor.article("Internal sensor")).isEqualTo("an Internal sensor");
  }
}
