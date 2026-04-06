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
public class LongSessionDetector {

  private static final long THRESHOLD_SECONDS = 900; // 15 minutes

  private final ConversationRepository conversationRepository;

  public List<Finding> detect(UUID fileId) {
    List<Object[]> rows = conversationRepository.findLongSessionsByFileId(fileId, THRESHOLD_SECONDS);
    List<Finding> findings = new ArrayList<>();

    for (Object[] row : rows) {
      String srcIp = String.valueOf(row[0]);
      String dstIp = row[1] != null ? String.valueOf(row[1]) : "?";
      Object dstPortObj = row[2];
      String protocol = String.valueOf(row[3]);
      String appName = row[4] != null ? String.valueOf(row[4]) : null;
      double durationMs = ((Number) row[5]).doubleValue();
      long totalBytes = ((Number) row[6]).longValue();
      long packetCount = ((Number) row[7]).longValue();

      long durationSec = (long) (durationMs / 1000);
      String durationStr = durationSec < 3600
          ? (durationSec / 60) + "m " + (durationSec % 60) + "s"
          : (durationSec / 3600) + "h " + ((durationSec % 3600) / 60) + "m";

      Severity severity = durationSec > 3600 ? Severity.HIGH : Severity.MEDIUM;
      Map<String, Object> metrics = new LinkedHashMap<>();
      metrics.put("durationMs", Math.round(durationMs));
      metrics.put("totalBytes", totalBytes);
      metrics.put("packetCount", packetCount);
      if (dstPortObj != null) metrics.put("dstPort", ((Number) dstPortObj).intValue());

      String appLabel = appName != null && !appName.isBlank() ? " [" + appName + "]" : "";
      findings.add(Finding.builder()
          .type(FindingType.LONG_SESSION)
          .severity(severity)
          .title(String.format("Long Session: %s → %s (%s%s, %s)", srcIp, dstIp, protocol, appLabel, durationStr))
          .summary(String.format(
              "Session from %s to %s lasted %s, transferring %d bytes across %d packets. Persistent sessions may indicate C2, data staging, or remote access.",
              srcIp, dstIp, durationStr, totalBytes, packetCount))
          .metrics(metrics)
          .affectedIps(List.of(srcIp, dstIp))
          .build());
    }
    return findings;
  }
}
