package com.tracepcap.story.spi;

import com.tracepcap.analysis.spi.AnalysisSummaryLookup.CaptureSummary;
import com.tracepcap.story.dto.Finding;
import com.tracepcap.story.dto.StoryAggregates;
import java.util.List;
import java.util.UUID;

/**
 * What a {@link Narrator} may read: the conclusions the earlier stages reached (#512).
 *
 * <p><b>Conclusions, not raw facts</b> — and the difference is the stage boundary. A narrator gets
 * findings a scanner judged and totals the pipeline measured, not a pile of packets to interpret.
 * Anything a narrator wishes it could work out for itself is a scanner that has not been written
 * yet: put the judgment where it can be tested and given a confidence, then narrate the result.
 *
 * <p>Everything here is read-only. Narrate is the last stage before a human reads the words; a
 * narrator that could edit the evidence would be rewriting the record to fit the story.
 */
public interface NarrationContext {

  /** The file being narrated. */
  UUID fileId();

  /**
   * The capture's totals — packets, bytes, duration. All MEASURED.
   *
   * <p>Never null: a file with no analysis summary never reaches Narrate.
   */
  CaptureSummary summary();

  /**
   * What the scanners concluded, most severe first.
   *
   * <p>All <b>INFERRED</b>: a finding is a judgment with known error modes, however deterministic
   * the code that produced it. A narrator writing "the host is compromised" from a finding that says
   * "traffic consistent with scanning" has upgraded a guess to a fact on the reader's behalf.
   *
   * <p>Empty means nothing was flagged — <em>not</em> that nothing happened.
   */
  List<Finding> findings();

  /**
   * Whole-capture aggregates: protocol mix, top external ASNs, TLS anomaly counts, beacon
   * candidates.
   *
   * <p>Never null — aggregation degrades to a fallback rather than returning nothing. Its
   * <em>fields</em> are another matter: read the nullable ones as the honest signals they are.
   * {@code unknownAppPct} is null when nDPI did not complete, meaning the share is
   * <em>unknowable</em> — not zero, and not 100% (#501).
   */
  StoryAggregates aggregates();

  /**
   * Free-text context the analyst supplied with the request, or null.
   *
   * <p><b>REPORTED, and from outside the capture entirely.</b> A narrator may use it to focus, never
   * to conclude: "the user says this host is a printer" is a claim about the world, not evidence
   * from the wire.
   */
  String analystContext();
}
