package com.tracepcap.story.service.detector;

import com.tracepcap.common.stage.Tier;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.FindingType;
import com.tracepcap.story.dto.Severity;
import com.tracepcap.story.service.detector.BeaconAnalysis.Candidate;
import com.tracepcap.story.service.detector.BeaconAnalysis.Scope;
import com.tracepcap.story.spi.ScanContext;
import com.tracepcap.story.spi.Scanner;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Reports hosts that talk to one destination on a suspiciously regular schedule — a host
 * <em>beaconing out</em>, not any regular traffic. What counts, and why an internal domain-controller
 * keepalive does not, lives in {@link BeaconAnalysis} (#823), which the Story aggregates panel shares
 * so the two cannot disagree. This class only turns candidates into findings.
 */
@Component
@RequiredArgsConstructor
public class BeaconDetector implements Scanner {

  private static final int MAX_FINDINGS = 5;
  private static final double CRITICAL_CV = 0.1;

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
    // Grouped from the context's shared conversation list rather than a bespoke query: the list is
    // loaded once for the whole scan run either way, so a second read would buy nothing.
    return BeaconAnalysis.analyse(context.conversations()).stream()
        .limit(MAX_FINDINGS)
        .map(BeaconDetector::toFinding)
        .collect(Collectors.toList());
  }

  private static Finding toFinding(Candidate c) {
    boolean outbound = c.scope() == Scope.OUTBOUND;
    long intervalSec = (long) (c.meanMs() / 1000);
    String interval =
        intervalSec < 60 ? intervalSec + "s" : (intervalSec / 60) + "m " + (intervalSec % 60) + "s";
    String port = c.serverPort() == null ? "*" : String.valueOf(c.serverPort());
    String proto = String.join("/", c.protocols().stream().filter(p -> !p.isEmpty()).toList());

    Map<String, Object> metrics = new LinkedHashMap<>();
    metrics.put("flowCount", c.flows());
    metrics.put("avgIntervalMs", Math.round(c.meanMs()));
    metrics.put("cv", Math.round(c.cv() * 1000.0) / 1000.0);
    metrics.put("dstPort", c.serverPort() == null ? null : String.valueOf(c.serverPort()));
    metrics.put("direction", outbound ? "outbound" : "internal");
    if (!proto.isEmpty()) metrics.put("protocolViews", new ArrayList<>(c.protocols()));

    String cadence =
        String.format(
            "%d flows, avg interval %s, jitter %.1f%% (CV=%.3f)", c.flows(), interval, c.cv() * 100, c.cv());

    Finding.FindingBuilder b =
        Finding.builder()
            .type(FindingType.BEACON)
            .metrics(metrics)
            .affectedIps(List.of(c.client(), c.server()));
    if (outbound) {
      return b.severity(c.cv() < CRITICAL_CV ? Severity.CRITICAL : Severity.HIGH)
          .title(String.format("Beacon: %s → %s:%s", c.client(), c.server(), port))
          .summary(
              String.format(
                  "%s connecting to %s:%s (%s) with %s — highly periodic traffic consistent with C2 keepalive.",
                  c.client(), c.server(), port, proto, cadence))
          .build();
    }
    // Internal: state the regularity, and say plainly that it is not, by itself, evidence of C2.
    return b.severity(Severity.MEDIUM)
        .title(String.format("Periodic internal traffic: %s → %s:%s", c.client(), c.server(), port))
        .summary(
            String.format(
                "%s connecting to internal host %s:%s (%s) with %s — regular traffic to an internal host"
                    + " on a non-service port that nDPI could not identify. Worth a look if that host is"
                    + " unexpected; not, by itself, an indicator of command and control.",
                c.client(), c.server(), port, proto, cadence))
        .build();
  }
}
