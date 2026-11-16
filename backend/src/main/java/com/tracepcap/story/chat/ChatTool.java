package com.tracepcap.story.chat;

import com.fasterxml.jackson.databind.JsonNode;
import com.tracepcap.story.service.LlmToolSpec;
import java.util.UUID;

/**
 * Something the capture chat can look up to answer a question (#1161). Read-only, and only on the
 * capture the chat is about: the capture is fixed by the server, never chosen by the model.
 *
 * <p>Implementations are Spring beans; the registry discovers them, so adding a tool is adding a
 * class. The same registry is meant to back an MCP server later.
 */
public interface ChatTool {

  /** The function name the model calls, snake_case. */
  String name();

  /** What the UI calls it, e.g. "Check a filter". */
  String label();

  /** One line for people: what it looks up. */
  String summary();

  /** A question it helps answer, shown in the tools list. */
  String example();

  /** The declaration the model sees: its description and typed arguments. */
  LlmToolSpec spec();

  /**
   * Runs it. Throw {@link IllegalArgumentException} for arguments the model got wrong; the message
   * goes back to the model so it can try again.
   */
  Result run(ChatToolContext context, JsonNode args);

  /**
   * What came back.
   *
   * @param summary one line for the step list, e.g. "valid · 50 packets match"
   * @param data what the model reads, serialised as JSON (kept small)
   * @param filter a checked display filter, when the tool produced one
   */
  record Result(String summary, Object data, CheckedFilter filter) {
    public static Result of(String summary, Object data) {
      return new Result(summary, data, null);
    }
  }

  /** A Wireshark display filter checked against the capture. */
  record CheckedFilter(String expression, boolean valid, Integer matches, String error) {}

  /** Which capture, and which network's rules it is read with. */
  record ChatToolContext(UUID fileId, UUID networkId) {}
}
