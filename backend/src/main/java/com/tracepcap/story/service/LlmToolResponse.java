package com.tracepcap.story.service;

import java.util.List;

/**
 * Outcome of a tool-enabled LLM call.
 *
 * <p>Two shapes, and callers must handle both: {@code schemaConstrained} means the server returned
 * real {@code tool_calls} generated against the declared schema, and {@link #toolCalls()} holds
 * them. Otherwise the server ignored, rejected, or was never offered the tools, and {@link
 * #content()} holds ordinary free text the caller must parse itself — the pre-#623 path, preserved
 * because not every local backend implements tool calling.
 *
 * @param toolCalls one entry per {@code tool_calls} element, empty on the free-text path
 * @param content assistant message text, null when the model answered purely with tool calls
 * @param schemaConstrained whether the arguments came from schema-constrained generation
 */
public record LlmToolResponse(List<ToolCall> toolCalls, String content, boolean schemaConstrained) {

  /**
   * A single tool invocation.
   *
   * @param name function name the model called
   * @param argumentsJson raw JSON arguments — a JSON string per the OpenAI wire format, not a
   *     decoded object
   */
  public record ToolCall(String name, String argumentsJson) {}

  /** The free-text fallback: no tool calls, caller parses {@code content} itself. */
  public static LlmToolResponse freeText(String content) {
    return new LlmToolResponse(List.of(), content, false);
  }

  public static LlmToolResponse constrained(List<ToolCall> toolCalls, String content) {
    return new LlmToolResponse(List.copyOf(toolCalls), content, true);
  }

  /** Tool calls naming {@code name}, in the order the model emitted them. */
  public List<ToolCall> callsTo(String name) {
    return toolCalls.stream().filter(c -> name.equals(c.name())).toList();
  }
}
