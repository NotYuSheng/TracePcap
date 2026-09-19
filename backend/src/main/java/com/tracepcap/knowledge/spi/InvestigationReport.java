package com.tracepcap.knowledge.spi;

import java.util.List;
import java.util.UUID;

/**
 * The outcome of an autonomous investigation over one capture (#819, L2): for every standing
 * {@link Goal}, what was concluded and how confidently, plus the goals still <em>open</em> and the
 * techniques that contributed. This is the product surface the narrative and the UI consume — it
 * makes "what we still don't know" a first-class, honest part of the answer, not an omission.
 */
public record InvestigationReport(
    UUID fileId, List<GoalOutcome> outcomes, List<String> coverage) {

  public InvestigationReport {
    outcomes = outcomes == null ? List.of() : List.copyOf(outcomes);
    coverage = coverage == null ? List.of() : List.copyOf(coverage);
  }

  /**
   * One goal's result. When {@code answered} is false the goal is an <em>unknown</em>: no technique
   * could satisfy it on this capture (an enrichment gap or simply absent evidence), and the fields
   * carry their empty defaults.
   */
  public record GoalOutcome(
      Goal goal,
      boolean answered,
      String headline,
      Grade grade,
      int confidence,
      List<String> basis,
      List<EntityRef> subjects) {

    public GoalOutcome {
      basis = basis == null ? List.of() : List.copyOf(basis);
      subjects = subjects == null ? List.of() : List.copyOf(subjects);
    }
  }

  /** The goals no technique could close on this capture — the investigation's honest gaps. */
  public List<Goal> openGoals() {
    return outcomes.stream().filter(o -> !o.answered()).map(GoalOutcome::goal).toList();
  }
}
