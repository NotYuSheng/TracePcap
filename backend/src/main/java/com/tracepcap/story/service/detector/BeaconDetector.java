package com.tracepcap.story.service.detector;

import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.FindingType;
import com.tracepcap.story.dto.Severity;
import com.tracepcap.story.spi.ScanContext;
import com.tracepcap.story.spi.Scanner;
import com.tracepcap.story.spi.Tier;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class BeaconDetector implements Scanner {

  @Override
  public String name() {
    return "beacon";
  }

  @Override
  public Tier tier() {
    return Tier.DETERMINISTIC;
  }

  @Override
  public List<Finding> scan(ScanContext context) {
    record FlowKey(String src, String dst, String port, String proto) {}
    // Grouped from the context's shared conversation list rather than a bespoke query: the list is
    // loaded once for the whole scan run either way, so a second read would buy nothing.
    Map<FlowKey, List<LocalDateTime>> groups = new HashMap<>();
    for (ConversationFacts c : context.conversations()) {
      FlowKey key =
          new FlowKey(
              c.flow().srcIp(),
              c.flow().dstIp() != null ? c.flow().dstIp() : "",
              c.flow().dstPort() != null ? String.valueOf(c.flow().dstPort()) : "",
              c.flow().protocol());
      groups.computeIfAbsent(key, k -> new ArrayList<>()).add(c.flow().startTime());
    }
    // The old query pre-sorted by start time; grouping in Java must sort explicitly, since the
    // interval maths below is meaningless on unordered timestamps.
    groups.values().forEach(java.util.Collections::sort);

    List<Finding> findings = new ArrayList<>();
    for (Map.Entry<FlowKey, List<LocalDateTime>> e : groups.entrySet()) {
      List<LocalDateTime> times = e.getValue();
      if (times.size() < 3) continue;

      List<Long> intervals = new ArrayList<>();
      for (int i = 1; i < times.size(); i++) {
        long ms = java.time.Duration.between(times.get(i - 1), times.get(i)).toMillis();
        if (ms >= 0) intervals.add(ms);
      }
      if (intervals.isEmpty()) continue;

      double mean = intervals.stream().mapToLong(Long::longValue).average().orElse(0);
      if (mean < 1000) continue;

      double variance =
          intervals.stream().mapToDouble(v -> Math.pow(v - mean, 2)).average().orElse(0);
      double cv = Math.sqrt(variance) / mean;
      if (cv >= 0.3) continue;

      FlowKey k = e.getKey();
      Severity severity = cv < 0.1 ? Severity.CRITICAL : Severity.HIGH;
      long intervalSec = (long) (mean / 1000);
      String interval =
          intervalSec < 60
              ? intervalSec + "s"
              : (intervalSec / 60) + "m " + (intervalSec % 60) + "s";

      Map<String, Object> metrics = new LinkedHashMap<>();
      metrics.put("flowCount", times.size());
      metrics.put("avgIntervalMs", Math.round(mean));
      metrics.put("cv", Math.round(cv * 1000.0) / 1000.0);
      metrics.put("dstPort", k.port().isEmpty() ? null : k.port());

      findings.add(
          Finding.builder()
              .type(FindingType.BEACON)
              .severity(severity)
              .title(
                  String.format(
                      "Beacon: %s → %s:%s",
                      k.src(),
                      k.dst().isEmpty() ? "?" : k.dst(),
                      k.port().isEmpty() ? "*" : k.port()))
              .summary(
                  String.format(
                      "%s connecting to %s:%s (%s) with %d flows, avg interval %s, jitter %.1f%% (CV=%.3f) — highly periodic traffic consistent with C2 keepalive.",
                      k.src(),
                      k.dst().isEmpty() ? "?" : k.dst(),
                      k.port().isEmpty() ? "*" : k.port(),
                      k.proto(),
                      times.size(),
                      interval,
                      cv * 100,
                      cv))
              .metrics(metrics)
              .affectedIps(
                  List.of(k.src(), k.dst()).stream()
                      .filter(s -> !s.isEmpty())
                      .collect(Collectors.toList()))
              .build());
    }

    findings.sort(
        Comparator.comparingDouble(
            f -> {
              Object cv = f.getMetrics() != null ? f.getMetrics().get("cv") : null;
              return cv instanceof Number ? ((Number) cv).doubleValue() : 1.0;
            }));
    return findings.stream().limit(5).collect(Collectors.toList());
  }
}
