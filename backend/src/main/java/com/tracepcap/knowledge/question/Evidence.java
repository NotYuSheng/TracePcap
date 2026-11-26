package com.tracepcap.knowledge.question;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Shapes an answer's basis for reading. */
final class Evidence {

  private Evidence() {}

  /**
   * One line per distinct piece of evidence, in first-seen order, with how many times it was seen:
   * a C2 that tripped the same rule 303 times is one line, "… (×303)", not 303. (The WarmCookie
   * training capture's C2 answer carried 312 lines for 6 distinct alerts.)
   */
  static List<String> collapse(List<String> lines) {
    Map<String, Integer> counts = new LinkedHashMap<>();
    for (String l : lines) if (l != null) counts.merge(l, 1, Integer::sum);
    return counts.entrySet().stream()
        .map(e -> e.getValue() > 1 ? e.getKey() + " (×" + e.getValue() + ")" : e.getKey())
        .toList();
  }
}
