package com.tracepcap.knowledge.spi;

/**
 * A standing investigation question the platform drives to close on every capture (#819, L2). A goal
 * is deliberately separate from the {@link StandardQuestion} that answers it: the goal is the
 * <em>objective</em> ("who is the victim?"), the question is one technique that can satisfy it. Making
 * goals first-class is what lets the orchestrator report not just what it found, but what it is still
 * <em>missing</em> — the honest "unknowns" an autonomous investigation must surface.
 *
 * <p>For the L2 slice the goal set is fixed and each maps to one deterministic question key; later
 * ladder rungs add goals (scope, entry vector, timeline) and multiple techniques per goal.
 */
public enum Goal {
  VICTIM("victim"),
  USER("signed-in-user"),
  MALWARE("malware"),
  C2("c2");

  private final String questionKey;

  Goal(String questionKey) {
    this.questionKey = questionKey;
  }

  /** The {@link StandardQuestion#question()} key whose answer satisfies this goal. */
  public String questionKey() {
    return questionKey;
  }
}
