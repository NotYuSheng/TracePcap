package com.tracepcap.story.service.detector;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.DetectionRuleCatalog;
import com.tracepcap.analysis.spi.NetworkRuleOverlay;
import com.tracepcap.story.dto.FindingType;
import com.tracepcap.story.dto.Severity;
import com.tracepcap.story.spi.ScanContext;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class DetectionRuleScannerTest {

  private static final UUID FILE = UUID.randomUUID();
  private static final UUID NET = UUID.randomUUID();

  private static ConversationFacts conv(UUID id, String src, String dst, long bytes, List<String> sigs) {
    var flow = new ConversationLookup.FlowIdentity(src, 1000, dst, 554, null, null, "TCP", 1, bytes, null, null);
    var findings = new ConversationLookup.Findings(null, null, null, List.of(), List.of(), sigs, List.of());
    return new ConversationFacts(id, FILE, flow, null, findings);
  }

  private final UUID c1 = UUID.randomUUID();
  private final UUID c2 = UUID.randomUUID();
  private final UUID c3 = UUID.randomUUID();
  private final List<ConversationFacts> convs =
      List.of(
          conv(c1, "10.0.0.5", "10.0.0.9", 100, List.of("rtsp", "old-disabled")),
          conv(c2, "10.0.0.6", "10.0.0.9", 50, List.of("rtsp")),
          conv(c3, "10.0.0.7", "8.8.8.8", 10, List.of()));

  private final DetectionRuleCatalog catalog =
      new DetectionRuleCatalog() {
        public Map<String, RuleSummary> rulesInEffect(UUID fileId, UUID networkId) {
          var rules = new java.util.LinkedHashMap<String, RuleSummary>();
          rules.put("rtsp", new RuleSummary("rtsp", "high", "RTSP video stream", "global"));
          if (networkId != null) rules.put("site-dns", new RuleSummary("site-dns", "critical", null, "HQ"));
          return rules;
        }
        public Optional<String> networkName(UUID networkId) { return Optional.of("HQ"); }
      };

  private final NetworkRuleOverlay overlay =
      new NetworkRuleOverlay() {
        public Map<UUID, List<String>> labels(UUID n, UUID f) { return Map.of(c3, List.of("site-dns")); }
        public Set<UUID> conversationsMatching(UUID n, UUID f, Collection<String> names) { return Set.of(); }
        public Set<String> suppressedNames(UUID n) { return Set.of(); }
        public Map<UUID, Set<String>> matchedNamesByFile(UUID n, Collection<UUID> f) { return Map.of(); }
      };

  private ScanContext context(UUID networkId) {
    return new ScanContext() {
      public UUID fileId() { return FILE; }
      public long totalConversations() { return convs.size(); }
      public long totalBytes() { return 160; }
      public List<ConversationFacts> conversations() { return convs; }
      public List<ConversationFacts> tlsConversations() { return List.of(); }
      public UUID networkId() { return networkId; }
    };
  }

  @Test
  void oneFindingPerRuleInEffect_withTheRulesSeverityAndDescription() {
    var findings = new DetectionRuleScanner(catalog, overlay).scan(context(null));
    assertThat(findings).hasSize(1); // "old-disabled" isn't in effect, so it doesn't count
    var f = findings.get(0);
    assertThat(f.getType()).isEqualTo(FindingType.DETECTION_RULE);
    assertThat(f.getSeverity()).isEqualTo(Severity.HIGH);
    assertThat(f.getTitle()).isEqualTo("Detection rule: rtsp [global]");
    assertThat(f.getSummary()).startsWith("RTSP video stream. 2 conversation(s)");
    assertThat(f.getMetrics()).containsEntry("totalBytes", 150L);
    assertThat(f.getAffectedIps()).first().isEqualTo("10.0.0.9"); // in both conversations
  }

  @Test
  void inANetwork_itsOwnRulesCount() {
    var findings = new DetectionRuleScanner(catalog, overlay).scan(context(NET));
    assertThat(findings).extracting(f -> f.getTitle())
        .containsExactlyInAnyOrder("Detection rule: rtsp [global]", "Detection rule: site-dns [HQ]");
    assertThat(findings).filteredOn(f -> f.getTitle().contains("site-dns")).first()
        .extracting(f -> f.getSeverity()).isEqualTo(Severity.CRITICAL);
  }
}
