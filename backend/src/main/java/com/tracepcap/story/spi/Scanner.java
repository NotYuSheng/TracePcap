package com.tracepcap.story.spi;

import com.tracepcap.story.dto.Finding;
import java.util.List;

/**
 * A Scan-stage module: reads the fact base, returns judgments (#512).
 *
 * <p><b>This is the seam the playbook is built on.</b> Every implementation is discovered by Spring
 * and run in turn, so <em>adding a scanner is adding one class</em> — no core to edit, no list to
 * append to, no registration call to remember. If you find yourself editing another file to make a
 * new scanner run, something here has broken and should be fixed rather than worked around.
 *
 * <p><b>Scanners are additive.</b> A new scanner never conflicts with an existing one; it just adds
 * findings. Two scanners disagreeing is not a bug — it is a contest, and resolving it belongs to the
 * Adjudicate stage, not here. Never edit another scanner to make room for yours.
 *
 * <p><b>Never read the pcap.</b> Scan reads facts that Extract already dug out; the capture may not
 * even exist any more. Everything a scanner needs arrives on {@link ScanContext}. If something is
 * missing there, the fix is an extractor plus a context accessor, not a shell out to tshark.
 *
 * <p><b>Degrade, do not fail.</b> One scanner throwing must not lose the other scanners' findings —
 * the runner isolates each call, but a scanner that cannot answer should prefer returning no
 * findings, or a finding that says the evidence was missing (see the {@code COVERAGE_GAP} pattern in
 * {@code UnknownAppDetector}: "the tool did not run" and "the tool found nothing" are different
 * answers, and #501 is what conflating them costs).
 */
public interface Scanner {

  /**
   * Stable identifier, used in logs and to attribute findings. Kebab-case, e.g. {@code
   * "beacon-detector"}. Changing it changes how this scanner's history reads, so pick once.
   */
  String name();

  /** How this scanner reaches its judgment — see {@link Tier}. */
  Tier tier();

  /**
   * Reads the facts on the context and returns what it concluded.
   *
   * <p>Never null; an empty list means "nothing to report", which is a real and common answer.
   * Findings are graded INFERRED by definition — a scanner's output is a judgment with known error
   * modes, never a measurement, however deterministic the code that produced it.
   */
  List<Finding> scan(ScanContext context);
}
