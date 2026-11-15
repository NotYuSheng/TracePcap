package com.tracepcap.report;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.ConversationLookup;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** A report row's rule tags as seen in a network (#925). */
class ReportNetworkRulesTest {

  @Test
  void dropsSuppressedGlobalRules_addsTheNetworksOwn() {
    var flow = new ConversationLookup.FlowIdentity("10.0.0.1", 1, "10.0.0.2", 2, null, null, "TCP", 1, 1, null, null);
    var findings =
        new ConversationLookup.Findings(null, null, null, List.of("risk"), List.of(), List.of("noisy", "kept"), List.of());
    var c = new ConversationLookup.ConversationFacts(UUID.randomUUID(), UUID.randomUUID(), flow, null, findings);
    var seen = ReportService.inNetwork(c, Set.of("noisy"), List.of("site-dns", "kept"));
    assertThat(seen.findings().customSignatures()).containsExactly("kept", "site-dns");
    assertThat(seen.findings().flowRisks()).containsExactly("risk");
  }
}
