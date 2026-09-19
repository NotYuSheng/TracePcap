package com.tracepcap.knowledge.spi;

import java.util.Map;

/**
 * A typed, directed edge between two entities — {@code from --predicate--> to} — carrying how it is
 * known ({@link Grade}) and which contributor posted it ({@code source}). Predicates are open
 * strings (e.g. {@code "signed-in-as"}, {@code "communicates-with"}) so a new relationship kind is
 * just a new label, not a schema change.
 */
public record Relationship(
    EntityRef from,
    String predicate,
    EntityRef to,
    Grade grade,
    String source,
    Map<String, Object> attributes) {

  public Relationship {
    if (from == null || to == null || predicate == null || predicate.isBlank()) {
      throw new IllegalArgumentException("Relationship needs from, predicate, and to");
    }
    if (grade == null) grade = Grade.INFERRED;
    attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
  }

  public static Relationship of(
      EntityRef from, String predicate, EntityRef to, Grade grade, String source) {
    return new Relationship(from, predicate, to, grade, source, Map.of());
  }
}
