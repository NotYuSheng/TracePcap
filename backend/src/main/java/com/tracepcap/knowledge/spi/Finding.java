package com.tracepcap.knowledge.spi;

import java.util.List;
import java.util.Map;

/**
 * A typed observation posted to the board — a Suricata hit, a beacon, a visibility gap. {@code
 * category} is an open label (e.g. {@code "ids-alert"}, {@code "periodicity"}); presenters render
 * generically off it, so a new detector's findings surface without wiring. {@code concerns} lists
 * the entities the finding is about, and {@code evidence} points back at the raw material
 * (conversation ids, packet refs) that justifies it.
 */
public record Finding(
    String category,
    String summary,
    Severity severity,
    Grade grade,
    String source,
    List<EntityRef> concerns,
    List<String> evidence,
    Map<String, Object> attributes) {

  public Finding {
    if (category == null || category.isBlank()) {
      throw new IllegalArgumentException("Finding needs a category");
    }
    if (summary == null) summary = "";
    if (severity == null) severity = Severity.INFO;
    if (grade == null) grade = Grade.INFERRED;
    concerns = concerns == null ? List.of() : List.copyOf(concerns);
    evidence = evidence == null ? List.of() : List.copyOf(evidence);
    attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
  }
}
