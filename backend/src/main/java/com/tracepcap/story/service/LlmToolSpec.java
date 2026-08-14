package com.tracepcap.story.service;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A tool the LLM may call, declared as an OpenAI-compatible {@code function} with a JSON-Schema
 * parameter object.
 *
 * <p>Declaring the shape server-side is the point: an OpenAI-compatible server that supports tools
 * constrains generation to this schema, so field names and types arrive correct rather than being
 * free-typed into a schema the model never saw (#623).
 *
 * @param name function name the model calls
 * @param description what the tool does — the model's only guide to when to call it
 * @param parameters JSON-Schema object describing the arguments
 */
public record LlmToolSpec(String name, String description, Map<String, Object> parameters) {

  /** Builder for the JSON-Schema {@code object} that types a tool's arguments. */
  public static final class SchemaBuilder {
    private final Map<String, Object> properties = new LinkedHashMap<>();
    private final List<String> required = new java.util.ArrayList<>();

    /**
     * Declare one property.
     *
     * @param name property name — must match the DTO field the arguments bind to
     * @param type JSON-Schema type ({@code string}, {@code integer}, {@code number}, {@code
     *     boolean})
     * @param description semantics the type cannot carry; the schema constrains shape, not meaning,
     *     so anything the model could misread (aggregate vs per-row, exact-match vs substring)
     *     belongs here
     */
    public SchemaBuilder property(String name, String type, String description) {
      properties.put(name, Map.of("type", type, "description", description));
      return this;
    }

    /** Declare a property whose value must be one of {@code values}. */
    public SchemaBuilder enumProperty(String name, String description, List<String> values) {
      properties.put(
          name, Map.of("type", "string", "description", description, "enum", List.copyOf(values)));
      return this;
    }

    /** Mark previously declared properties as required. */
    public SchemaBuilder require(String... names) {
      required.addAll(List.of(names));
      return this;
    }

    public Map<String, Object> build() {
      Map<String, Object> schema = new LinkedHashMap<>();
      schema.put("type", "object");
      schema.put("properties", Map.copyOf(properties));
      schema.put("required", List.copyOf(required));
      // Local backends vary in how strictly they honour this, but where it is honoured it stops the
      // model inventing fields that InvestigationQuery has no place to put.
      schema.put("additionalProperties", false);
      return schema;
    }
  }

  public static SchemaBuilder schema() {
    return new SchemaBuilder();
  }
}
