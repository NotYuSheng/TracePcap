package com.tracepcap.knowledge.spi;

import java.util.Map;

/**
 * A node on the board: something the capture is about. Attributes are an open bag so a contributor
 * can describe an entity however its source allows without a schema change — the extensibility the
 * board is built for. Merged by {@link #ref} when more than one contributor describes the same node.
 */
public record Entity(EntityRef ref, Map<String, Object> attributes) {
  public Entity {
    if (ref == null) throw new IllegalArgumentException("Entity needs a ref");
    attributes = attributes == null ? Map.of() : Map.copyOf(attributes);
  }

  public EntityType type() {
    return ref.type();
  }

  public String key() {
    return ref.key();
  }
}
