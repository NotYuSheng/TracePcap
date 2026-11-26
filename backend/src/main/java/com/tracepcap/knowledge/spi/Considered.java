package com.tracepcap.knowledge.spi;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A candidate a check tested and ruled out (#1294): the reputation-listed server that wasn't a C2,
 * the beacon whose stream matched no known family, the host four failed sign-ins short of spraying.
 * A good report says why the other candidates aren't the answer; this is what lets it.
 *
 * <p>Posted on the board as a finding of category {@link #CATEGORY} (a contributor never reaches a
 * question), and read back with {@link #from}. Never a conclusion: nothing reads one as a finding.
 *
 * @param question the standard question it was a candidate for ("c2", "kerberos-attack")
 * @param candidate what was tested ("45.125.66.40", "10.0.0.5 → 10.0.0.10")
 * @param rule the rule it was tested against, in words
 * @param reason why it fell short ("reached once, not in repeated rounds")
 */
public record Considered(
    String question, String candidate, String rule, String reason, List<String> conversations) {

  public static final String CATEGORY = "considered";

  public Considered {
    conversations = conversations == null ? List.of() : List.copyOf(new java.util.LinkedHashSet<>(conversations));
  }

  /** As a board finding, about {@code concerns}. */
  public Finding toFinding(String source, List<EntityRef> concerns) {
    Map<String, Object> attrs = new LinkedHashMap<>();
    attrs.put("question", question);
    attrs.put("candidate", candidate);
    if (rule != null) attrs.put("rule", rule);
    attrs.put("reason", reason);
    return new Finding(CATEGORY, candidate + ": " + reason, Severity.INFO, Grade.INFERRED, source,
        concerns, conversations, attrs);
  }

  /** Back from a board finding; null for a finding of another category. */
  public static Considered from(Finding f) {
    if (!CATEGORY.equals(f.category())) return null;
    Map<String, Object> a = f.attributes();
    return new Considered(str(a.get("question")), str(a.get("candidate")), str(a.get("rule")),
        str(a.get("reason")), f.evidence());
  }

  private static String str(Object o) {
    return o == null ? null : o.toString();
  }
}
