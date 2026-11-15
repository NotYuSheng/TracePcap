package com.tracepcap.story.service.detector;

import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.DetectionRuleCatalog;
import com.tracepcap.analysis.spi.NetworkRuleOverlay;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.FindingType;
import com.tracepcap.story.dto.Severity;
import com.tracepcap.story.spi.ScanContext;
import com.tracepcap.story.spi.Scanner;
import com.tracepcap.common.stage.Tier;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Detection-rule matches as Story findings (#925): one finding per rule that matched, with the
 * rule's own severity and description. Uses the rules in effect: global (minus those a network
 * suppresses), the capture's own, and, viewed in a network, the network's own.
 */
@Component
@RequiredArgsConstructor
public class DetectionRuleScanner implements Scanner {

  private static final int MAX_AFFECTED_IPS = 10;

  private final DetectionRuleCatalog catalog;
  private final NetworkRuleOverlay overlay;

  @Override
  public String name() {
    return "detection-rule";
  }

  @Override
  public Tier tier() {
    return Tier.DETERMINISTIC;
  }

  /** Per-rule tallies over the capture's conversations. */
  private static final class Tally {
    long conversations;
    long bytes;
    final Set<String> sources = new HashSet<>();
    final Set<String> destinations = new HashSet<>();
    final Map<String, Integer> ipHits = new HashMap<>();
  }

  @Override
  public List<Finding> scan(ScanContext context) {
    UUID fileId = context.fileId();
    UUID networkId = context.networkId();
    Map<String, DetectionRuleCatalog.RuleSummary> rules = catalog.rulesInEffect(fileId, networkId);
    if (rules.isEmpty()) return List.of();
    Map<UUID, List<String>> networkLabels = networkId == null ? Map.of() : overlay.labels(networkId, fileId);

    Map<String, Tally> tallies = new LinkedHashMap<>();
    for (ConversationFacts c : context.conversations()) {
      Set<String> names = new LinkedHashSet<>();
      if (c.findings() != null && c.findings().customSignatures() != null) names.addAll(c.findings().customSignatures());
      names.addAll(networkLabels.getOrDefault(c.id(), List.of()));
      for (String name : names) {
        // Only rules in effect: a disabled, deleted or suppressed rule's stored matches don't count.
        if (!rules.containsKey(name)) continue;
        Tally t = tallies.computeIfAbsent(name, k -> new Tally());
        t.conversations++;
        t.bytes += c.flow().totalBytes();
        if (c.flow().srcIp() != null) {
          t.sources.add(c.flow().srcIp());
          t.ipHits.merge(c.flow().srcIp(), 1, Integer::sum);
        }
        if (c.flow().dstIp() != null) {
          t.destinations.add(c.flow().dstIp());
          t.ipHits.merge(c.flow().dstIp(), 1, Integer::sum);
        }
      }
    }

    List<Finding> out = new ArrayList<>();
    tallies.forEach(
        (name, t) -> {
          var rule = rules.get(name);
          Map<String, Object> metrics = new LinkedHashMap<>();
          metrics.put("rule", name);
          metrics.put("scope", rule.scope());
          metrics.put("conversationCount", t.conversations);
          metrics.put("totalBytes", t.bytes);
          metrics.put("distinctSrcIps", t.sources.size());
          metrics.put("distinctDstIps", t.destinations.size());
          String what = rule.description() == null || rule.description().isBlank() ? "" : rule.description().trim() + ". ";
          out.add(
              Finding.builder()
                  .type(FindingType.DETECTION_RULE)
                  .severity(severity(rule.severity()))
                  .title("Detection rule: " + name + " [" + rule.scope() + "]")
                  .summary(
                      String.format(
                          "%s%d conversation(s) matched across %d source IP(s) and %d destination IP(s), totalling %d bytes.",
                          what, t.conversations, t.sources.size(), t.destinations.size(), t.bytes))
                  .metrics(metrics)
                  .affectedIps(
                      t.ipHits.entrySet().stream()
                          .sorted(Map.Entry.<String, Integer>comparingByValue(Comparator.reverseOrder())
                              .thenComparing(Map.Entry.comparingByKey()))
                          .limit(MAX_AFFECTED_IPS)
                          .map(Map.Entry::getKey)
                          .toList())
                  .build());
        });
    return out;
  }

  static Severity severity(String ruleSeverity) {
    if (ruleSeverity == null) return Severity.LOW;
    return switch (ruleSeverity.toLowerCase()) {
      case "critical" -> Severity.CRITICAL;
      case "high" -> Severity.HIGH;
      case "medium" -> Severity.MEDIUM;
      default -> Severity.LOW;
    };
  }
}
