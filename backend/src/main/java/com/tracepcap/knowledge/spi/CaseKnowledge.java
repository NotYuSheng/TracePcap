package com.tracepcap.knowledge.spi;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * The assembled, read-only knowledge board for one capture — every entity, relationship, and
 * finding its contributors posted. This is what deterministic checks query and what the narrator
 * (eventually) reads instead of hand-picking a few lookups. The query helpers are intentionally
 * simple: a check asks "what malware findings are there?" or "who is this host signed in as?"
 * without walking the raw lists itself.
 */
public record CaseKnowledge(
    UUID fileId, List<Entity> entities, List<Relationship> relationships, List<Finding> findings) {

  public CaseKnowledge {
    entities = entities == null ? List.of() : List.copyOf(entities);
    relationships = relationships == null ? List.of() : List.copyOf(relationships);
    findings = findings == null ? List.of() : List.copyOf(findings);
  }

  /** Every entity of the given type. */
  public List<Entity> entitiesOfType(EntityType type) {
    return entities.stream().filter(e -> e.type() == type).toList();
  }

  /** The entity with this exact ref, if any contributor described it. */
  public Optional<Entity> entity(EntityRef ref) {
    return entities.stream().filter(e -> e.ref().equals(ref)).findFirst();
  }

  /** Every finding in the given category (e.g. {@code "ids-alert"}). */
  public List<Finding> findingsOfCategory(String category) {
    return findings.stream().filter(f -> category.equals(f.category())).toList();
  }

  /** Every relationship with the given predicate (e.g. {@code "signed-in-as"}). */
  public List<Relationship> relationshipsWithPredicate(String predicate) {
    return relationships.stream().filter(r -> predicate.equals(r.predicate())).toList();
  }

  /** Outgoing relationships from an entity with the given predicate. */
  public List<Relationship> relationshipsFrom(EntityRef from, String predicate) {
    return relationships.stream()
        .filter(r -> r.from().equals(from) && predicate.equals(r.predicate()))
        .toList();
  }
}
