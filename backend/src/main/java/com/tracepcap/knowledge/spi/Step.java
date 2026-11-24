package com.tracepcap.knowledge.spi;

import java.util.List;

/**
 * One step in how a {@link StandardQuestion} reached its answer (#1293): what it found, and the rule
 * that took it from there to the next claim. An answer's steps, in order, are the reasoning an
 * analyst can check, so "a deterministic check, not the LLM" is shown rather than asserted.
 *
 * @param found what the check observed on the board ("Suricata rule ET MALWARE STRRAT CnC Checkin
 *     fired on 172.16.1.66 → 141.98.10.79")
 * @param rule the reasoning applied to it ("A malware rule that names a server makes it that
 *     family's C2"), or null when the step is context rather than inference
 * @param grade how directly what was found is known
 * @param conversations the conversations it rests on, for links; may be empty
 */
public record Step(String found, String rule, Grade grade, List<String> conversations) {

  public Step {
    if (found == null || found.isBlank()) throw new IllegalArgumentException("A step needs what was found");
    if (grade == null) grade = Grade.INFERRED;
    // Once each: a finding's evidence can name a conversation twice.
    conversations = conversations == null ? List.of() : List.copyOf(new java.util.LinkedHashSet<>(conversations));
  }

  public static Step of(String found, String rule, Grade grade) {
    return new Step(found, rule, grade, List.of());
  }
}
