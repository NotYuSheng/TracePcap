package com.tracepcap.knowledge.spi;

/**
 * A knowledge source that runs <em>after</em> the board is assembled and augments it in response to
 * what the producers found (#819, L2). Where a {@link KnowledgeContributor} posts facts from the raw
 * capture in one independent pass, a pivot <b>reads the board and follows a lead</b> — a suspected
 * beacon, an unattributed external — deriving more, so a goal a producer could not close gets closed.
 * This is what makes the investigation a chain rather than a flat scatter of facts.
 *
 * <p>The orchestrator runs applicable pivots to a fixpoint, so a pivot must be idempotent: reading a
 * board it has already acted on, it should add nothing (typically by checking whether the artifact it
 * would post is already present). Like every knowledge source it communicates only through the board
 * and is isolated — one that throws is logged and skipped, never failing the investigation.
 */
public interface InvestigativePivot {

  /** Stable identifier, used as the {@code source} on artifacts this pivot posts. */
  String name();

  /** Whether this pivot has a lead to follow on the current board — cheap, side-effect-free. */
  boolean appliesTo(CaseKnowledge board);

  /**
   * Reads {@code board} and posts any new artifacts to {@code out} (already seeded with the board).
   * Must not re-post what the board already carries.
   */
  void pivot(CaseKnowledge board, CaseKnowledgeBuilder out);
}
