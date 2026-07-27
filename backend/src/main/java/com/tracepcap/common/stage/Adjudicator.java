package com.tracepcap.common.stage;

import java.util.UUID;

/**
 * An Adjudicate-stage module: answers one question with one voice (#512).
 *
 * <p><b>Exclusive, not additive — the rule that makes this stage different.</b> Scanners pile up:
 * a new one never conflicts, it just adds findings. Adjudicators may not. Exactly one module answers
 * "what is this host?", exactly one answers "what is its name?", and a second claiming a question
 * already taken is a <em>conflict</em>, not an addition. The runner enforces that at startup rather
 * than trusting it: two voices answering one question is the bug this stage exists to prevent, so
 * discovery alone would be the wrong contract here.
 *
 * <p><b>Weigh by grade, and rank humans first.</b> A conclusion built from MEASURED facts outranks
 * one built from REPORTED testimony — a host's DHCP-claimed name is what it says about itself, and
 * hosts lie. A human-confirmed annotation outranks everything: that is what "AI-assisted human
 * annotators" means structurally rather than aspirationally.
 *
 * <p><b>Contested is a legal answer.</b> When the evidence genuinely does not settle a question, say
 * so and carry the candidates. A confident wrong answer is worse than an honest "these two disagree"
 * — the analyst can act on the second and is misled by the first. #498 is the cost of hiding it.
 *
 * <p><b>Conclusions are revisable.</b> Facts change as new snapshots arrive, so adjudication is not
 * a one-shot: the runner re-runs on analysis completion and on annotation changes. Staleness is not
 * a bolt-on — it <em>is</em> re-adjudication.
 *
 * <p><b>The loop rule.</b> Consuming another stage's adjudication is allowed — device identity only
 * survives IP churn as an adjudicated question — but treat it as INFERRED unless a human confirmed
 * it. Machine conclusions inform; they must never self-reinforce at full weight (#507).
 */
public interface Adjudicator {

  /**
   * The question this module answers, kebab-case — {@code "host-identity"}, {@code "hostname"}.
   *
   * <p><b>This is the exclusivity key.</b> It is not a display name: two adjudicators returning the
   * same string is a startup failure, because it means two modules claim the last word on one
   * question and the answer would depend on bean order.
   */
  String question();

  /** How this adjudicator reaches its answer — see {@link Tier}. */
  Tier tier();

  /**
   * Re-answers this question for a file, persisting the conclusion.
   *
   * <p>Must be idempotent: the runner calls it on every analysis completion and every annotation
   * change, so the same inputs must yield the same conclusion rather than accumulating.
   */
  void adjudicate(UUID fileId);
}
