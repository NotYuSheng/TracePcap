package com.tracepcap.analysis.service;

import com.tracepcap.analysis.spi.ExtractionTarget;
import com.tracepcap.analysis.spi.Extractor;
import com.tracepcap.common.stage.Tier;
import com.tracepcap.file.entity.FileEntity;
import java.io.File;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

/**
 * Runs every {@link Extractor} on the classpath against one capture.
 *
 * <p><b>It names no extractor.</b> Spring injects every implementation, so a new extractor is one
 * new class and nothing here changes (#512). {@code AnalysisService} used to hold a field per
 * extractor, an {@code if} per enable flag, and a manifest call per branch; adding an extractor
 * meant editing the pipeline's core, which is the thing this architecture exists to prevent.
 *
 * <p>Two jobs beyond looping:
 *
 * <ul>
 *   <li><b>The manifest is automatic.</b> Every extractor with a key gets a row, every run —
 *       including when it is skipped, and including when it throws. An extractor cannot forget, and
 *       forgetting is what makes "the tool found nothing" indistinguishable from "the tool never
 *       ran" (#501).
 *   <li><b>Failures are isolated.</b> One extractor throwing costs its own facts and nothing else;
 *       the capture is still worth analysing without one enrichment.
 * </ul>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ExtractorRunner {

  private final List<Extractor> extractors;
  private final ExtractionRunService extractionRunService;

  /**
   * Runs the enabled extractors in {@link Extractor#order()} order, writing their facts onto {@code
   * conversations} and recording each one's provenance.
   */
  public void runAll(FileEntity file, File capture, List<PcapParserService.ConversationInfo> conversations) {
    ExtractionTarget target = new Target(file, capture, conversations);
    List<Extractor> ordered =
        extractors.stream().sorted(Comparator.comparingInt(Extractor::order)).toList();

    for (Extractor extractor : ordered) {
      long started = System.currentTimeMillis();
      try {
        if (!extractor.enabledFor(target)) {
          // Skipped is a real answer, not an absence — record it so downstream can tell the two
          // apart rather than inferring "found nothing" from a missing row.
          record(extractor, file.getId(), Extractor.Outcome.skipped("not enabled for this file"));
          continue;
        }
        Extractor.Outcome outcome = extractor.extract(target);
        record(extractor, file.getId(), outcome);
        log.debug(
            "[{}] extractor {} -> {} ({}ms)",
            file.getId(),
            extractor.name(),
            outcome.status(),
            System.currentTimeMillis() - started);
      } catch (Exception e) {
        // The whole exception, not getMessage(): an NPE's message is null, and "ndpi failed: null"
        // helps nobody at 3am.
        log.warn("[{}] extractor {} failed", file.getId(), extractor.name(), e);
        record(
            extractor,
            file.getId(),
            Extractor.Outcome.failed(e.getClass().getSimpleName() + ": " + e.getMessage()));
      }
    }

    log.info(
        "[{}] Extract: {} extractors ({})", file.getId(), ordered.size(), tierBreakdown(ordered));
  }

  /** Records provenance for extractors that claim a manifest key; the rest pass silently. */
  private void record(Extractor extractor, UUID fileId, Extractor.Outcome outcome) {
    String key = extractor.manifestKey();
    if (key == null) return;
    extractionRunService.record(fileId, key, outcome.status(), outcome.detail());
  }

  /** The stage's shape by tier, logged so the deterministic/LLM balance stays visible. */
  private static String tierBreakdown(List<Extractor> extractors) {
    return extractors.stream()
        .collect(Collectors.groupingBy(Extractor::tier, Collectors.counting()))
        .entrySet()
        .stream()
        .sorted(Comparator.comparing(e -> e.getKey().name()))
        .map(e -> e.getValue() + " " + e.getKey())
        .collect(Collectors.joining(", "));
  }

  /** The target handed to each extractor. Not a bean: one per capture. */
  private record Target(
      FileEntity file, File capture, List<PcapParserService.ConversationInfo> conversations)
      implements ExtractionTarget {

    @Override
    public UUID fileId() {
      return file.getId();
    }
  }

  /** Exposed for the extract-registry test: which extractors Spring discovered. */
  List<String> registeredExtractorNames() {
    return extractors.stream().map(Extractor::name).sorted().toList();
  }

  /** Exposed for the extract-registry test: the tier each discovered extractor declares. */
  List<Tier> registeredTiers() {
    return extractors.stream().map(Extractor::tier).toList();
  }
}
