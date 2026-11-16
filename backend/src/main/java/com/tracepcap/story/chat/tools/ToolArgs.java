package com.tracepcap.story.chat.tools;

import com.fasterxml.jackson.databind.JsonNode;

/** Reading the model's arguments leniently: missing or blank means not given. */
final class ToolArgs {
  private ToolArgs() {}

  static String text(JsonNode args, String name) {
    JsonNode v = args == null ? null : args.get(name);
    if (v == null || v.isNull()) return null;
    String s = v.asText().trim();
    return s.isEmpty() ? null : s;
  }

  static Integer integer(JsonNode args, String name) {
    JsonNode v = args == null ? null : args.get(name);
    if (v == null || v.isNull()) return null;
    if (v.isNumber()) return v.asInt();
    try {
      return Integer.parseInt(v.asText().trim());
    } catch (NumberFormatException e) {
      return null;
    }
  }

  static Boolean bool(JsonNode args, String name) {
    JsonNode v = args == null ? null : args.get(name);
    if (v == null || v.isNull()) return null;
    return v.isBoolean() ? v.asBoolean() : Boolean.parseBoolean(v.asText());
  }

  static int limit(JsonNode args, int fallback, int max) {
    Integer n = integer(args, "limit");
    return n == null || n < 1 ? fallback : Math.min(n, max);
  }
}
