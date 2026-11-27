package com.tracepcap.insights.service;

import java.util.Map;
import java.util.stream.Collectors;

/** How a change event's old and new values read in an insight prompt (network and snapshot). */
final class ChangeEventText {

  private ChangeEventText() {}

  /** "vendor=Dell, type=LAPTOP", or "—" for none. */
  static String value(Map<String, Object> value) {
    if (value == null) return "—";
    return value.entrySet().stream()
        .map(e -> e.getKey() + "=" + e.getValue())
        .collect(Collectors.joining(", "));
  }
}
