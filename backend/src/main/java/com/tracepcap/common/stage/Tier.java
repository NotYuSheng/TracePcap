package com.tracepcap.common.stage;

/**
 * How a module reaches its answer (#512).
 *
 * <p>Determinism is not a stage — every stage holds all three tiers, which is why this lives in
 * {@code common.stage} rather than with any one of them: an extractor and a scanner answer to the
 * same three words. A module declares its own tier rather than being told, because the tier is a
 * property of how it works, and only the module knows that.
 *
 * <p>The point of naming it is honesty about cost and trust: a reader deserves to know whether a
 * finding came from arithmetic, from a language model's guess, or from a person. It also makes the
 * suite's shape visible — if the LLM tier grows while the deterministic tier does not, that is worth
 * seeing rather than discovering later.
 *
 * <p><b>Prefer {@link #DETERMINISTIC}.</b> An LLM must earn its place by doing something determinism
 * cannot, not by being easier to write.
 */
public enum Tier {

  /**
   * Arithmetic, thresholds, pattern matching. Same facts in, same answer out, every time — and
   * explainable to a user in one sentence.
   */
  DETERMINISTIC,

  /**
   * Reaches its answer through a language model. Not reproducible run to run, costs a call, and can
   * be confidently wrong — so it must be reserved for questions determinism genuinely cannot answer
   * (open-ended narrative, "does this look odd", natural-language questions).
   */
  LLM,

  /**
   * Proposes, but a human confirms before the answer counts. The tier the annotation workflow lives
   * in: the module does the tedious part, a person supplies the judgment, and the result carries
   * that person's authority rather than the machine's.
   */
  HUMAN_ASSISTED
}
