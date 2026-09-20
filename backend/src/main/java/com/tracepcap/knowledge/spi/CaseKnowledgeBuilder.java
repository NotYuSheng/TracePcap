package com.tracepcap.knowledge.spi;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * The mutable board a {@link KnowledgeContributor} posts to. Contributors never call each other —
 * they only add here, blackboard-style, and the assembler hands the same builder to each one in
 * turn. Entities are merged by {@link EntityRef}: two contributors describing the same host
 * accumulate their attributes onto one node (later writes win per key), so no contributor has to
 * know what another already said.
 */
public final class CaseKnowledgeBuilder {

  private final UUID fileId;
  private final Map<EntityRef, Map<String, Object>> entities = new LinkedHashMap<>();
  private final List<Relationship> relationships = new ArrayList<>();
  private final List<Finding> findings = new ArrayList<>();

  public CaseKnowledgeBuilder(UUID fileId) {
    this.fileId = fileId;
  }

  /**
   * Seeds this builder with everything already on an assembled board — for a stage that <em>augments</em>
   * a board (the pivot loop, #819) rather than assembling from scratch. Entities merge by ref as usual.
   */
  public CaseKnowledgeBuilder addAll(CaseKnowledge board) {
    if (board == null) return this;
    board.entities().forEach(e -> addEntity(e.ref(), e.attributes()));
    board.relationships().forEach(this::addRelationship);
    board.findings().forEach(this::addFinding);
    return this;
  }

  /** Records (or merges into) an entity node. Null-safe: a null ref is ignored. */
  public CaseKnowledgeBuilder addEntity(EntityRef ref, Map<String, Object> attributes) {
    if (ref == null) return this;
    Map<String, Object> merged = entities.computeIfAbsent(ref, k -> new LinkedHashMap<>());
    if (attributes != null) {
      attributes.forEach(
          (k, v) -> {
            if (k != null && v != null) merged.put(k, v);
          });
    }
    return this;
  }

  /** Convenience for an entity with no attributes yet (e.g. just asserting it exists). */
  public CaseKnowledgeBuilder addEntity(EntityRef ref) {
    return addEntity(ref, Map.of());
  }

  public CaseKnowledgeBuilder addRelationship(Relationship relationship) {
    if (relationship != null) {
      // Ensure both endpoints exist as nodes, even if no contributor described them directly.
      addEntity(relationship.from());
      addEntity(relationship.to());
      relationships.add(relationship);
    }
    return this;
  }

  public CaseKnowledgeBuilder addFinding(Finding finding) {
    if (finding != null) {
      finding.concerns().forEach(this::addEntity);
      findings.add(finding);
    }
    return this;
  }

  public CaseKnowledge build() {
    List<Entity> built = new ArrayList<>(entities.size());
    entities.forEach((ref, attrs) -> built.add(new Entity(ref, attrs)));
    return new CaseKnowledge(fileId, built, List.copyOf(relationships), List.copyOf(findings));
  }
}
