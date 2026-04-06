package com.tracepcap.story.service.detector;

import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.FindingType;
import com.tracepcap.story.dto.Severity;
import java.util.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class NdpiRiskDetector {

  private static final Set<String> CRITICAL_RISKS = Set.of(
      "possible_exploit_detected", "binary_application_transfer",
      "clear_text_credentials", "suspicious_entropy");
  private static final Set<String> HIGH_RISKS = Set.of(
      "suspicious_dns_traffic", "dns_suspicious_traffic",
      "malicious_sha1_certificate", "malformed_packet");
  private static final Set<String> MEDIUM_RISKS = Set.of(
      "self_signed_certificate", "obsolete_tls_version",
      "weak_tls_cipher", "tls_certificate_about_to_expire");

  private final ConversationRepository conversationRepository;

  public List<Finding> detect(UUID fileId) {
    List<Object[]> rows = conversationRepository.findRiskTypeStatsByFileId(fileId);
    List<Finding> findings = new ArrayList<>();
    for (Object[] row : rows) {
      String riskType = String.valueOf(row[0]);
      long convCount = ((Number) row[1]).longValue();
      long bytes = ((Number) row[2]).longValue();
      long srcIps = ((Number) row[3]).longValue();
      long dstIps = ((Number) row[4]).longValue();

      Severity severity = classifySeverity(riskType);
      Map<String, Object> metrics = new LinkedHashMap<>();
      metrics.put("conversationCount", convCount);
      metrics.put("totalBytes", bytes);
      metrics.put("distinctSrcIps", srcIps);
      metrics.put("distinctDstIps", dstIps);

      findings.add(Finding.builder()
          .type(FindingType.NDPI_RISK)
          .severity(severity)
          .title("nDPI Risk: " + riskType.replace('_', ' '))
          .summary(String.format(
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
