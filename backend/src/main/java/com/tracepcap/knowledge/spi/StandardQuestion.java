package com.tracepcap.knowledge.spi;

import java.util.List;
import java.util.Set;

/**
 * A deterministic check that answers one standard investigation question by querying the {@link
 * CaseKnowledge} board (#813) — the primary analysis layer, and the reason most of the value needs
 * no LLM. Each is a small class, auto-discovered like a contributor, and (because its input and
 * output are both deterministic) unit-testable against a fixture board.
 *
 * <p>A knowledge source in the blackboard sense: it reads the board and posts conclusions, never
 * calling another check. Adding a question is adding one class. A question that the board can't
 * answer returns an empty list — silence, not a guess.
 */
public interface StandardQuestion {

  /** Stable key for this question, e.g. {@code "victim"}, {@code "c2"}. Kebab-case. */
  String question();

  /** Zero or more answers this question can support from the board (e.g. multiple victims). */
  List<Answer> answer(CaseKnowledge board);

  /**
   * The framework categories this question answers (docs/architecture/investigation-framework.rst).
   * One check can answer several: a C2 is both a host role and the Command and Control tactic.
   */
  default Set<Category> categories() {
    return Set.of();
  }

  /**
   * The traffic this question reads, each with what it shows for it. A capture with none of it
   * can't answer the question, so its categories are not observable there. Empty: it reads no
   * particular protocol (IDS alerts on any traffic, say).
   */
  default List<EvidenceSource> requires() {
    return List.of();
  }
}
