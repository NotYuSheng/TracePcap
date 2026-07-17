package com.tracepcap.story.service.detector;

import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.FindingType;
import com.tracepcap.story.dto.Severity;
import com.tracepcap.story.spi.ScanContext;
import com.tracepcap.story.spi.Scanner;
import com.tracepcap.story.spi.Tier;
import java.util.*;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

@Component
public class PortProtocolMismatchDetector implements Scanner {

  // app_name (nDPI) → expected destination ports
  private static final Map<String, Set<Integer>> EXPECTED_PORTS =
      Map.of(
          "DNS", Set.of(53),
          "HTTP", Set.of(80, 8080, 8000, 8888),
          "HTTPS", Set.of(443, 8443),
          "FTP", Set.of(20, 21),
          "SSH", Set.of(22),
          "SMTP", Set.of(25, 465, 587),
          "IMAP", Set.of(143, 993),
          "RDP", Set.of(3389),
          "TELNET", Set.of(23));

  @Override
  public String name() {
    return "port-protocol-mismatch";
  }

  @Override
  public Tier tier() {
    return Tier.DETERMINISTIC;
  }

  @Override
  public List<Finding> scan(ScanContext context) {
    List<ConversationFacts> conversations = context.conversations();
    // Group mismatches by (appName, dstPort)
    record MismatchKey(String app, int port) {}
    Map<MismatchKey, List<ConversationFacts>> mismatches = new LinkedHashMap<>();

    for (ConversationFacts conv : conversations) {
      if (conv.findings().appName() == null || conv.flow().dstPort() == null) continue;
      String app = conv.findings().appName().toUpperCase();
      Set<Integer> expected = EXPECTED_PORTS.get(app);
      if (expected == null) continue;
      int port = conv.flow().dstPort();
      if (!expected.contains(port)) {
        mismatches.computeIfAbsent(new MismatchKey(app, port), k -> new ArrayList<>()).add(conv);
      }
    }

    List<Finding> findings = new ArrayList<>();
    for (Map.Entry<MismatchKey, List<ConversationFacts>> e : mismatches.entrySet()) {
      MismatchKey key = e.getKey();
      List<ConversationFacts> convs = e.getValue();
      List<String> affectedIps =
          convs.stream()
              .map(c -> c.flow().srcIp())
              .distinct()
              .limit(5)
              .collect(Collectors.toList());
      long totalBytes = convs.stream().mapToLong(c -> c.flow().totalBytes()).sum();

      Map<String, Object> metrics = new LinkedHashMap<>();
      metrics.put("conversationCount", convs.size());
      metrics.put("totalBytes", totalBytes);
      metrics.put("nonStandardPort", key.port());

      findings.add(
          Finding.builder()
              .type(FindingType.PORT_PROTOCOL_MISMATCH)
              .severity(Severity.HIGH)
              .title(String.format("Port Mismatch: %s on port %d", key.app(), key.port()))
              .summary(
                  String.format(
                      "%d %s conversation(s) detected on non-standard port %d — may indicate port evasion, tunnelling, or misconfiguration.",
                      convs.size(), key.app(), key.port()))
              .metrics(metrics)
              .affectedIps(affectedIps)
              .build());
    }
    return findings;
  }
}
