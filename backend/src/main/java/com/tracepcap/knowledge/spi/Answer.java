package com.tracepcap.knowledge.spi;

import java.util.List;
import java.util.Map;

/**
 * A conclusion a {@link StandardQuestion} drew from the board — the output of the deterministic
 * analysis layer (#813). Distinct from a {@link Finding}: a finding is an <em>observation</em> a
 * contributor posted (data); an answer is a <em>conclusion</em> a check reached by querying those
 * observations. Every answer carries the {@code subjects} it names, the {@code grade} it inherits
 * from the artifacts it was built on, and a {@code basis} — the human-readable "why" — so it can be
 * shown and audited, never asserted bare.
 */
public record Answer(
    String question,
    String headline,
    Grade grade,
    List<EntityRef> subjects,
    List<String> basis,
    Map<String, Object> attributes) {

  public Answer {
    if (question == null || question.isBlank()) {
      throw new IllegalArgumentException("Answer needs a question key");
    }
    if (headline == null) headline = "";
    if (grade == null) grade = Grade.INFERRED;
    subjects = subjects == null ? List.of() : List.copyOf(subjects);
    basis = basis == null ? List.of() : List.copyOf(basis);
    attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
  }
}
