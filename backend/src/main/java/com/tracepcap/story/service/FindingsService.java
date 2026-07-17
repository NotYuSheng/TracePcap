package com.tracepcap.story.service;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.Severity;
import com.tracepcap.story.spi.ScanContext;
import com.tracepcap.story.spi.Scanner;
import com.tracepcap.story.spi.Tier;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Runs every {@link Scanner} on the classpath and returns their merged, severity-sorted findings.
 *
 * <p><b>It names no scanner.</b> Spring injects every implementation, so a new scanner is one new
 * class and nothing here changes — which is the whole point of the registry (#512). This class used
 * to hold eight detector fields and eight call lines; adding a ninth meant editing it, and that is
 * exactly the "edit a core to add capability" the architecture exists to prevent.
 *
 * <p>Scanners are isolated from each other: one throwing loses its own findings and nothing else.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class FindingsService {

  private final List<Scanner> scanners;
  private final ConversationLookup conversationLookup;

  public List<Finding> detectAll(UUID fileId, long totalConversations, long totalBytes) {
    ScanContext context =
        new LazyScanContext(fileId, totalConversations, totalBytes, conversationLookup);

    List<Finding> findings = new ArrayList<>();
    for (Scanner scanner : scanners) {
      try {
        findings.addAll(scanner.scan(context));
      } catch (Exception e) {
        // One scanner's failure must not cost the others their findings.
        log.warn("Scanner {} failed: {}", scanner.name(), e.getMessage());
      }
    }

    // Severity first (CRITICAL leads), then type — a stable order regardless of scanner order,
    // which matters now that the order is whatever Spring hands us rather than a hand-written list.
    findings.sort(
        Comparator.comparingInt((Finding f) -> f.getSeverity().ordinal())
            .thenComparing(f -> f.getType().name()));

    log.info(
        "Findings for file {}: {} total from {} scanners ({}) — {} CRITICAL, {} HIGH, {} MEDIUM,"
            + " {} LOW",
        fileId,
        findings.size(),
        scanners.size(),
        tierBreakdown(),
        count(findings, Severity.CRITICAL),
        count(findings, Severity.HIGH),
        count(findings, Severity.MEDIUM),
        count(findings, Severity.LOW));
    return findings;
  }

  /**
   * The suite's shape by tier, e.g. {@code "9 DETERMINISTIC"}. Logged per run so the balance is
   * visible: an LLM tier that grows while the deterministic tier does not is worth noticing.
   */
  private String tierBreakdown() {
    return scanners.stream()
        .collect(Collectors.groupingBy(Scanner::tier, Collectors.counting()))
        .entrySet()
        .stream()
        .sorted(Comparator.comparing(e -> e.getKey().name()))
        .map(e -> e.getValue() + " " + e.getKey())
        .collect(Collectors.joining(", "));
  }

  private long count(List<Finding> findings, Severity severity) {
    return findings.stream().filter(f -> f.getSeverity() == severity).count();
  }

  /** Exposed for the scan-registry test: which scanners Spring actually discovered. */
  List<String> registeredScannerNames() {
    return scanners.stream().map(Scanner::name).sorted().toList();
  }

  /** Exposed for the scan-registry test: the tier each discovered scanner declares. */
  List<Tier> registeredTiers() {
    return scanners.stream().map(Scanner::tier).toList();
  }
}
