package com.tracepcap.story.service.detector;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.HostFanOut;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.FindingType;
import com.tracepcap.story.dto.Severity;
import com.tracepcap.story.spi.ScanContext;
import com.tracepcap.story.spi.Scanner;
import com.tracepcap.common.stage.Tier;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/** Flags hosts reaching many distinct destinations — the scanning / lateral-movement shape. */
@Component
@RequiredArgsConstructor
public class FanOutDetector implements Scanner {

  /** Past this many distinct destinations, fan-out stops looking like ordinary client traffic. */
  private static final long HIGH_SEVERITY_DESTINATIONS = 50;

  private final ConversationLookup conversationLookup;

  @Override
  public String name() {
    return "fan-out";
  }

  @Override
  public Tier tier() {
    return Tier.DETERMINISTIC;
  }

  @Override
  public List<Finding> scan(ScanContext context) {
    List<Finding> findings = new ArrayList<>();

    for (HostFanOut host : conversationLookup.fanOutCandidates(context.fileId())) {
      Map<String, Object> metrics = new LinkedHashMap<>();
      metrics.put("distinctDstIps", host.distinctDestinations());
      metrics.put("totalFlows", host.totalFlows());

      findings.add(
          Finding.builder()
              .type(FindingType.FAN_OUT)
              .severity(
                  host.distinctDestinations() > HIGH_SEVERITY_DESTINATIONS
                      ? Severity.HIGH
                      : Severity.MEDIUM)
              .title(
                  String.format(
                      "Fan-Out: %s → %d distinct destinations",
                      host.srcIp(), host.distinctDestinations()))
              .summary(
                  String.format(
                      "%s initiated %d flows to %d distinct destination IPs — pattern consistent"
                          + " with scanning or lateral movement.",
                      host.srcIp(), host.totalFlows(), host.distinctDestinations()))
              .metrics(metrics)
              .affectedIps(List.of(host.srcIp()))
              .build());
    }
    return findings;
  }
}
