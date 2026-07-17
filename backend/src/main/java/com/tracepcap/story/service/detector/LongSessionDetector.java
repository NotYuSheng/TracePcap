package com.tracepcap.story.service.detector;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.LongSession;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.FindingType;
import com.tracepcap.story.dto.Severity;
import com.tracepcap.story.spi.ScanContext;
import com.tracepcap.story.spi.Scanner;
import com.tracepcap.common.stage.Tier;
import java.util.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class LongSessionDetector implements Scanner {

  private static final long THRESHOLD_SECONDS = 900; // 15 minutes

  private final ConversationLookup conversationLookup;

  @Override
  public String name() {
    return "long-session";
  }

  @Override
  public Tier tier() {
    return Tier.DETERMINISTIC;
  }

  @Override
  public List<Finding> scan(ScanContext context) {
    List<Finding> findings = new ArrayList<>();

    for (LongSession row : conversationLookup.longSessions(context.fileId(), THRESHOLD_SECONDS)) {
      String srcIp = row.srcIp();
      String dstIp = row.dstIp() != null ? row.dstIp() : "?";
      Object dstPortObj = row.dstPort();
      String protocol = row.protocol();
      String appName = row.appName();
      double durationMs = row.durationMs();
      long totalBytes = row.totalBytes();
      long packetCount = row.packetCount();

      long durationSec = (long) (durationMs / 1000);
      String durationStr =
          durationSec < 3600
              ? (durationSec / 60) + "m " + (durationSec % 60) + "s"
              : (durationSec / 3600) + "h " + ((durationSec % 3600) / 60) + "m";

      Severity severity = durationSec > 3600 ? Severity.HIGH : Severity.MEDIUM;
      Map<String, Object> metrics = new LinkedHashMap<>();
      metrics.put("durationMs", Math.round(durationMs));
      metrics.put("totalBytes", totalBytes);
      metrics.put("packetCount", packetCount);
      if (dstPortObj != null) metrics.put("dstPort", ((Number) dstPortObj).intValue());

      String appLabel = appName != null && !appName.isBlank() ? " [" + appName + "]" : "";
      findings.add(
          Finding.builder()
              .type(FindingType.LONG_SESSION)
              .severity(severity)
              .title(
                  String.format(
                      "Long Session: %s → %s (%s%s, %s)",
                      srcIp, dstIp, protocol, appLabel, durationStr))
              .summary(
                  String.format(
                      "Session from %s to %s lasted %s, transferring %d bytes across %d packets. Persistent sessions may indicate C2, data staging, or remote access.",
                      srcIp, dstIp, durationStr, totalBytes, packetCount))
              .metrics(metrics)
              .affectedIps(List.of(srcIp, dstIp))
              .build());
    }
    return findings;
  }
}
