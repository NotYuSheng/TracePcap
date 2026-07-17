package com.tracepcap.story.service.detector;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.RiskTypeStats;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.FindingType;
import com.tracepcap.story.dto.Severity;
import com.tracepcap.story.spi.ScanContext;
import com.tracepcap.story.spi.Scanner;
import com.tracepcap.story.spi.Tier;
import java.util.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class NdpiRiskDetector implements Scanner {

  private static final Set<String> CRITICAL_RISKS =
      Set.of(
          "possible_exploit_detected", "binary_application_transfer",
          "clear_text_credentials", "suspicious_entropy");
  private static final Set<String> HIGH_RISKS =
      Set.of(
          "suspicious_dns_traffic", "dns_suspicious_traffic",
          "malicious_sha1_certificate", "malformed_packet");
  private static final Set<String> MEDIUM_RISKS =
      Set.of(
          "self_signed_certificate", "obsolete_tls_version",
          "weak_tls_cipher", "tls_certificate_about_to_expire");

  private final ConversationLookup conversationLookup;

  @Override
  public String name() {
    return "ndpi-risk";
  }

  @Override
  public Tier tier() {
    return Tier.DETERMINISTIC;
  }

  @Override
  public List<Finding> scan(ScanContext context) {
    List<Finding> findings = new ArrayList<>();
    for (RiskTypeStats row : conversationLookup.riskTypeStats(context.fileId())) {
      String riskType = row.riskType();
      long convCount = row.conversationCount();
      long bytes = row.totalBytes();
      long srcIps = row.distinctSourceIps();
      long dstIps = row.distinctDestinationIps();

      Severity severity = classifySeverity(riskType);
      Map<String, Object> metrics = new LinkedHashMap<>();
      metrics.put("conversationCount", convCount);
      metrics.put("totalBytes", bytes);
      metrics.put("distinctSrcIps", srcIps);
      metrics.put("distinctDstIps", dstIps);

      findings.add(
          Finding.builder()
              .type(FindingType.NDPI_RISK)
              .severity(severity)
              .title("nDPI Risk: " + riskType.replace('_', ' '))
              .summary(
                  String.format(
                      "%d conversation(s) flagged with risk '%s' across %d source IP(s) and %d destination IP(s), totalling %d bytes.",
                      convCount, riskType, srcIps, dstIps, bytes))
              .metrics(metrics)
              .affectedIps(List.of())
              .build());
    }
    return findings;
  }

  private Severity classifySeverity(String riskType) {
    if (CRITICAL_RISKS.contains(riskType)) return Severity.CRITICAL;
    if (HIGH_RISKS.contains(riskType)) return Severity.HIGH;
    if (MEDIUM_RISKS.contains(riskType)) return Severity.MEDIUM;
    return Severity.LOW;
  }
}
