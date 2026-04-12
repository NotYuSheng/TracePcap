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
public class UnknownAppDetector {

  private final ConversationRepository conversationRepository;

  public List<Finding> detect(UUID fileId, long totalConversations) {
    if (totalConversations == 0) return List.of();
    long unknown = conversationRepository.countUnknownAppByFileId(fileId);
    double pct = (unknown * 100.0) / totalConversations;

    if (pct < 5.0) return List.of();

    Severity severity = pct > 30 ? Severity.HIGH : pct > 10 ? Severity.MEDIUM : Severity.LOW;
    Map<String, Object> metrics = new LinkedHashMap<>();
    metrics.put("unknownCount", unknown);
    metrics.put("totalConversations", totalConversations);
    metrics.put("pct", Math.round(pct * 10.0) / 10.0);

    return List.of(
        Finding.builder()
            .type(FindingType.UNKNOWN_APP)
            .severity(severity)
            .title(String.format("%.1f%% of Traffic Has Unknown Application", pct))
            .summary(
                String.format(
                    "%d of %d conversations (%,.1f%%) could not be identified by nDPI. Unclassified traffic limits visibility and may conceal tunnelling or custom protocols.",
                    unknown, totalConversations, pct))
            .metrics(metrics)
            .affectedIps(List.of())
            .build());
  }
}
