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
    UUID fileId, List<GoalOutcome> outcomes, List<Answer> additional, List<String> coverage,
    // Candidates the checks tested and ruled out, with why (#1294).
    List<Considered> considered) {

  public InvestigationReport {
    outcomes = outcomes == null ? List.of() : List.copyOf(outcomes);
    additional = additional == null ? List.of() : List.copyOf(additional);
    coverage = coverage == null ? List.of() : List.copyOf(coverage);
    considered = considered == null ? List.of() : List.copyOf(considered);
  }

  public InvestigationReport(
      UUID fileId, List<GoalOutcome> outcomes, List<Answer> additional, List<String> coverage) {
    this(fileId, outcomes, additional, coverage, List.of());
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
      List<EntityRef> subjects,
      // The answer's structured detail (a C2's address and how it was concluded, say), so a goal
      // renders like any other answer instead of losing it (#1264).
      java.util.Map<String, Object> attributes,
      // How the answer was reached (#1293), so the goal shows it like any other answer.
      List<Step> derivation) {

    public GoalOutcome {
      basis = basis == null ? List.of() : List.copyOf(basis);
      subjects = subjects == null ? List.of() : List.copyOf(subjects);
      attributes = attributes == null ? java.util.Map.of() : java.util.Collections.unmodifiableMap(new java.util.LinkedHashMap<>(attributes));
      derivation = derivation == null ? List.of() : List.copyOf(derivation);
    }

    public GoalOutcome(
        Goal goal, boolean answered, String headline, Grade grade, int confidence, List<String> basis,
        List<EntityRef> subjects, java.util.Map<String, Object> attributes) {
      this(goal, answered, headline, grade, confidence, basis, subjects, attributes, List.of());
    }

    public GoalOutcome(
        Goal goal, boolean answered, String headline, Grade grade, int confidence, List<String> basis,
        List<EntityRef> subjects) {
      this(goal, answered, headline, grade, confidence, basis, subjects, java.util.Map.of());
    }
  }

  /** The goals no technique could close on this capture — the investigation's honest gaps. */
  public List<Goal> openGoals() {
    return outcomes.stream().filter(o -> !o.answered()).map(GoalOutcome::goal).toList();
  }
}
