package com.tracepcap.story.spi;

import com.tracepcap.story.dto.NarrativeSection;
import java.util.List;

/**
 * A Narrate-stage module: turns conclusions into something a person can read (#512).
 *
 * <p><b>Additive, like Scan.</b> A new narrator adds sections; it never rewrites another's. Two
 * narrators covering the same ground is redundant, not a conflict — unlike Adjudicate, where a
 * second voice on one question is a bug. Every implementation is discovered and asked to contribute,
 * so adding a narrator is adding one class.
 *
 * <p><b>Narrate reads conclusions; it does not reach new ones.</b> If a narrator finds itself
 * deciding whether a host is a web server, that judgment belongs in Scan or Adjudicate, where it can
 * be tested, contested and given a confidence. A narrator that judges is a scanner nobody can
 * inspect — and its judgment reaches the user with the authority of prose.
 *
 * <p><b>Say what the evidence supports and no more.</b> Every input carries a grade: MEASURED facts
 * were exhibited, REPORTED ones were asserted by a party that may be lying, INFERRED ones are a
 * tool's guess. A narrator that renders "the host is called printer-01" from a DHCP claim has
 * silently promoted testimony to fact. Prefer "the host identified itself as".
 *
 * <p><b>Absence of evidence is not evidence of absence.</b> A capture is a keyhole: drops,
 * truncation and one-sided flows mean "no Suricata alerts" means "none were raised", never "nothing
 * happened". Narrators are the last stage before a human reads the words, so this is where that
 * distinction is finally kept or lost.
 *
 * <p><b>Contribute nothing rather than pad.</b> An empty list is a good answer when a narrator has
 * nothing to say about a capture. A section that exists to fill a slot costs the reader attention
 * and teaches them to skim.
 */
public interface Narrator {

  /**
   * Stable identifier, used in logs and to attribute sections. Kebab-case, e.g. {@code
   * "executive-summary"}. Changing it changes how this narrator's history reads, so pick once.
   */
  String name();

  /** How this narrator reaches its words — see {@link com.tracepcap.common.stage.Tier}. */
  com.tracepcap.common.stage.Tier tier();

  /**
   * Where this narrator's sections sit in the finished story. Lower comes first; the default is the
   * middle, which is where a narrator with no opinion belongs.
   *
   * <p>Unlike extractor ordering, this is presentation only — no narrator reads another's output, so
   * a wrong number is a worse read, not a wrong answer.
   */
  default int order() {
    return 100;
  }

  /**
   * Contributes this narrator's sections, or an empty list when it has nothing to say about the
   * capture.
   *
   * <p>Never null. The runner isolates failures: one narrator throwing costs its own sections and
   * nothing else, because a story missing one section still beats no story at all.
   */
  List<NarrativeSection> narrate(NarrationContext context);
}
