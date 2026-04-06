package com.tracepcap.story.service.detector;

import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.FindingType;
import com.tracepcap.story.dto.Severity;
import com.tracepcap.story.service.TlsAnomalyUtil;
import java.util.*;
import java.util.stream.Collectors;
import org.springframework.stereotype.Component;

@Component
public class TlsAnomalyDetector {

  public List<Finding> detect(List<ConversationEntity> tlsConversations) {
    List<Finding> findings = new ArrayList<>();

    List<ConversationEntity> selfSigned = tlsConversations.stream()
        .filter(TlsAnomalyUtil::isSelfSigned).collect(Collectors.toList());
    List<ConversationEntity> expired = tlsConversations.stream()
        .filter(TlsAnomalyUtil::isExpired).collect(Collectors.toList());
    List<ConversationEntity> unknownCa = tlsConversations.stream()
        .filter(c -> !TlsAnomalyUtil.isSelfSigned(c) && TlsAnomalyUtil.isUnknownCa(c))
        .collect(Collectors.toList());

    if (!selfSigned.isEmpty()) {
      List<String> ips = selfSigned.stream().map(ConversationEntity::getDstIp)
          .filter(Objects::nonNull).distinct().limit(5).collect(Collectors.toList());
      Map<String, Object> metrics = new LinkedHashMap<>();
      metrics.put("count", selfSigned.size());
      metrics.put("totalTlsFlows", tlsConversations.size());
      findings.add(Finding.builder()
          .type(FindingType.TLS_ANOMALY)
          .severity(Severity.HIGH)
          .title(String.format("TLS: %d Self-Signed Certificate(s)", selfSigned.size()))
          .summary(String.format(
              "%d TLS flow(s) use self-signed certificates (issuer == subject), out of %d total TLS flows. Self-signed certificates bypass CA validation.",
              selfSigned.size(), tlsConversations.size()))
          .metrics(metrics)
          .affectedIps(ips)
          .build());
    }

    if (!expired.isEmpty()) {
      List<String> ips = expired.stream().map(ConversationEntity::getDstIp)
          .filter(Objects::nonNull).distinct().limit(5).collect(Collectors.toList());
      Map<String, Object> metrics = new LinkedHashMap<>();
      metrics.put("count", expired.size());
      metrics.put("totalTlsFlows", tlsConversations.size());
      findings.add(Finding.builder()
          .type(FindingType.TLS_ANOMALY)
          .severity(Severity.HIGH)
          .title(String.format("TLS: %d Expired Certificate(s)", expired.size()))
          .summary(String.format(
              "%d TLS flow(s) present expired certificates, out of %d total TLS flows.",
              expired.size(), tlsConversations.size()))
          .metrics(metrics)
          .affectedIps(ips)
          .build());
    }

    if (!unknownCa.isEmpty()) {
      List<String> ips = unknownCa.stream().map(ConversationEntity::getDstIp)
          .filter(Objects::nonNull).distinct().limit(5).collect(Collectors.toList());
      Map<String, Object> metrics = new LinkedHashMap<>();
      metrics.put("count", unknownCa.size());
      metrics.put("totalTlsFlows", tlsConversations.size());
      findings.add(Finding.builder()
          .type(FindingType.TLS_ANOMALY)
          .severity(Severity.MEDIUM)
          .title(String.format("TLS: %d Unknown/Untrusted CA(s)", unknownCa.size()))
          .summary(String.format(
              "%d TLS flow(s) present certificates from unknown or untrusted issuers, out of %d total TLS flows.",
              unknownCa.size(), tlsConversations.size()))
          .metrics(metrics)
          .affectedIps(ips)
          .build());
    }

    return findings;
  }
}
