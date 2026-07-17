package com.tracepcap.story.service.detector;

import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.FindingType;
import com.tracepcap.story.dto.Severity;
import com.tracepcap.story.spi.ScanContext;
import com.tracepcap.story.spi.Scanner;
import com.tracepcap.story.spi.Tier;
import com.tracepcap.story.service.TlsAnomalyUtil;
import java.util.*;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

@Component
public class TlsAnomalyDetector implements Scanner {

  @Override
  public String name() {
    return "tls-anomaly";
  }

  @Override
  public Tier tier() {
    return Tier.DETERMINISTIC;
  }

  @Override
  public List<Finding> scan(ScanContext context) {
    List<ConversationFacts> tlsConversations = context.tlsConversations();
    List<Finding> findings = new ArrayList<>();

    List<ConversationFacts> selfSigned =
        tlsConversations.stream().filter(TlsAnomalyUtil::isSelfSigned).collect(Collectors.toList());
    List<ConversationFacts> expired =
        tlsConversations.stream().filter(TlsAnomalyUtil::isExpired).collect(Collectors.toList());
    List<ConversationFacts> unknownCa =
        tlsConversations.stream()
            .filter(c -> !TlsAnomalyUtil.isSelfSigned(c) && TlsAnomalyUtil.isUnknownCa(c))
            .collect(Collectors.toList());

    if (!selfSigned.isEmpty()) {
      List<String> ips =
          selfSigned.stream()
              .map(c -> c.flow().dstIp())
              .filter(Objects::nonNull)
              .distinct()
              .limit(5)
              .collect(Collectors.toList());
      Map<String, Object> metrics = new LinkedHashMap<>();
      metrics.put("count", selfSigned.size());
      metrics.put("totalTlsFlows", tlsConversations.size());
      findings.add(
          Finding.builder()
              .type(FindingType.TLS_ANOMALY)
              .severity(Severity.HIGH)
              .title(String.format("TLS: %d Self-Signed Certificate(s)", selfSigned.size()))
              .summary(
                  String.format(
                      "%d TLS flow(s) use self-signed certificates (issuer == subject), out of %d total TLS flows. Self-signed certificates bypass CA validation.",
                      selfSigned.size(), tlsConversations.size()))
              .metrics(metrics)
              .affectedIps(ips)
              .build());
    }

    if (!expired.isEmpty()) {
      List<String> ips =
          expired.stream()
              .map(c -> c.flow().dstIp())
              .filter(Objects::nonNull)
              .distinct()
              .limit(5)
              .collect(Collectors.toList());
      Map<String, Object> metrics = new LinkedHashMap<>();
      metrics.put("count", expired.size());
      metrics.put("totalTlsFlows", tlsConversations.size());
      findings.add(
          Finding.builder()
              .type(FindingType.TLS_ANOMALY)
              .severity(Severity.HIGH)
              .title(String.format("TLS: %d Expired Certificate(s)", expired.size()))
              .summary(
                  String.format(
                      "%d TLS flow(s) present expired certificates, out of %d total TLS flows.",
                      expired.size(), tlsConversations.size()))
              .metrics(metrics)
              .affectedIps(ips)
              .build());
    }

    if (!unknownCa.isEmpty()) {
      List<String> ips =
          unknownCa.stream()
              .map(c -> c.flow().dstIp())
              .filter(Objects::nonNull)
              .distinct()
              .limit(5)
              .collect(Collectors.toList());
      Map<String, Object> metrics = new LinkedHashMap<>();
      metrics.put("count", unknownCa.size());
      metrics.put("totalTlsFlows", tlsConversations.size());
      findings.add(
          Finding.builder()
              .type(FindingType.TLS_ANOMALY)
              .severity(Severity.MEDIUM)
              .title(String.format("TLS: %d Unknown/Untrusted CA(s)", unknownCa.size()))
              .summary(
                  String.format(
                      "%d TLS flow(s) present certificates from unknown or untrusted issuers, out of %d total TLS flows.",
                      unknownCa.size(), tlsConversations.size()))
              .metrics(metrics)
              .affectedIps(ips)
              .build());
    }

    return findings;
  }
}
