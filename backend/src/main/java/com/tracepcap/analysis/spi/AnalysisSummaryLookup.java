package com.tracepcap.analysis.spi;

import java.time.LocalDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Read port for a file's whole-capture summary (#512 slice 6d) — the totals the pipeline computed
 * once, rather than facts about any single conversation.
 *
 * <p>All <b>MEASURED</b>: counted or timed off the capture, not concluded from it.
 *
 * <p>Narrower than the stored row on purpose. {@code AnalysisResultEntity} also carries {@code
 * status} and {@code errorMessage} — pipeline bookkeeping that belongs to whoever runs the pipeline,
 * not to a consumer reading totals. A module that needs to know whether analysis succeeded should
 * ask about the file's state, not infer it from a summary row.
 */
public interface AnalysisSummaryLookup {

  /**
   * A capture's totals.
   *
   * <p>{@code protocolStats} maps a protocol name to its stats (the shape the pipeline wrote as
   * jsonb); it is never null and is immutable — the underlying column deserialises to a mutable map,
   * and a consumer must not be able to edit the fact base by writing through it. Times may be null
   * for a capture with no timestamped packets.
   */
  record CaptureSummary(
      long packetCount,
      long totalBytes,
      LocalDateTime startTime,
      LocalDateTime endTime,
      Long durationMs,
      Map<String, Object> protocolStats) {}

  /** The summary for a file, or empty when the file has not been analysed. */
  Optional<CaptureSummary> summaryFor(UUID fileId);
}
