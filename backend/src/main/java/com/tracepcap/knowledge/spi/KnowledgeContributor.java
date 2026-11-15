package com.tracepcap.knowledge.spi;


/**
 * A knowledge source (blackboard sense): it reads what its own library produced for a capture and
 * posts the resulting entities / relationships / findings onto the shared board. Contributors never
 * call each other — they communicate only through the board — which is exactly what lets "add a new
 * library" mean "add one contributor" with zero changes to any consumer (#813).
 *
 * <p>Every implementation is auto-discovered by Spring and run by {@code CaseKnowledgeService}, in
 * the spirit of the {@code Extractor} / {@code DeviceClassificationSignal} beans. Read from {@code
 * analysis.spi} ports, never from another module's repositories or entities.
 *
 * <p><b>Degrade, do not fail.</b> A contributor that cannot produce anything (its source is empty,
 * a lookup errored) must simply add nothing — the assembler isolates each one, but a contributor
 * that throws still adds noise to the logs and provides no board data, so prefer returning quietly.
 */
public interface KnowledgeContributor {

  /** Stable identifier for logging and to attribute the artifacts this source posts. Kebab-case. */
  String name();

  /**
   * Reads this source's output for {@code context.fileId()} and posts artifacts onto {@code board}.
   * Read the file's facts through {@code context}, not a lookup of your own: they are loaded once
   * and shared across every contributor in the assembly (#816).
   */
  void contribute(KnowledgeContext context, CaseKnowledgeBuilder board);
}
