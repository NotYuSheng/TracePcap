package com.tracepcap.analysis.spi;

import com.tracepcap.analysis.service.PcapParserService;
import java.util.List;

import com.tracepcap.common.stage.Tier;

/**
 * An Extract-stage module: digs facts out of the capture (#512).
 *
 * <p><b>The widest surface in the architecture, by design.</b> One protocol quirk is one extractor
 * and zero downstream changes — LLMNR, 802.1Q, DHCPv6, Kerberos, SMB, per-flow entropy. Every
 * implementation is discovered and run, so adding one is adding one class.
 *
 * <p><b>Extract writes; Scan reads.</b> An extractor mutates the conversations on its {@link
 * ExtractionTarget} in place, before they are persisted — that is the whole job. It must not judge
 * what it finds: "port 443 carried TLS" is extraction, "this host is a web server" is a Scan-stage
 * conclusion. Mixing the two is what {@code WebServerLogExtractor} does wrong today, and #496 is the
 * bill for it.
 *
 * <p><b>Record what you observed, not what you concluded.</b> Facts are graded at schema level:
 * MEASURED (the traffic exhibited it), REPORTED (a party asserted it — a DHCP hostname is testimony,
 * and hosts lie), INFERRED (a tool judged it — nDPI's app name is a guess with error modes). An
 * extractor that upgrades testimony to measurement corrupts every stage downstream.
 *
 * <p><b>Never pick a winner.</b> Two conflicting claims are both stored; a claim erased at write
 * time can never be scanned or adjudicated. Conflict <em>is</em> the signal — an ARP spoof is an
 * IP/MAC conflict, an impersonation is a hostname/certificate conflict.
 *
 * <p><b>Degrade, do not fail.</b> The runner isolates each extractor, but an extractor that cannot
 * run should return a {@link Outcome} saying so rather than throw: the manifest row is what lets
 * downstream tell "the tool found nothing" from "the tool never ran" (#501).
 */
public interface Extractor {

  /**
   * Stable identifier, used in logs and to attribute facts. Kebab-case, e.g. {@code "ndpi"}.
   * Changing it changes how this extractor's history reads, so pick once.
   */
  String name();

  /** How this extractor reaches its facts — see {@link Tier}. */
  Tier tier();

  /**
   * Whether this extractor should run for this capture.
   *
   * <p>The module decides, not the runner. An extractor's enabling conditions are its own business —
   * a per-file flag, a global kill-switch, a capture too large to be worth it — and a runner that
   * asked "is this the nDPI one?" would be exactly the core-editing this registry exists to remove.
   *
   * <p>Returning false is not a failure: the runner records a SKIPPED manifest row, which is a
   * different and equally important answer from "ran and found nothing".
   */
  boolean enabledFor(ExtractionTarget target);

  /**
   * The manifest key this extractor owns (see {@link ExtractionManifest}), or null when it records
   * no provenance.
   *
   * <p>Prefer a key. Without one, downstream cannot distinguish "this extractor found nothing" from
   * "this extractor never ran", and conflating those is a bug with a number (#501).
   */
  default String manifestKey() {
    return null;
  }

  /**
   * When this extractor runs, relative to its peers. Lower goes first; the default is the middle of
   * the range, which is where an extractor with no opinion belongs.
   *
   * <p><b>The weak point of this design, stated plainly.</b> Extractors are not all independent —
   * tshark enrichment reads fields nDPI populates, so it must follow it. A global integer expresses
   * that badly: it is invisible from either module, and two extractors that both "want to be late"
   * have no way to say why. A declared dependency ({@code dependsOn(NDPI)}) would say what is
   * actually meant. That is a bigger change than this slice, and the {@link Extractor} contract is
   * what matters — ordering can become explicit later without touching any extractor's logic.
   */
  default int order() {
    return 100;
  }

  /**
   * Digs facts out of the capture and writes them onto the target's conversations.
   *
   * <p>Never null. The returned {@link Outcome} lands in the manifest as this extractor's provenance
   * for the file.
   */
  Outcome extract(ExtractionTarget target);

  /**
   * Optional first phase: the slow work that needs only the capture file, run before the pipeline
   * opens its database transaction (#409).
   *
   * <p>Most of an analysis is external tools reading the capture (Suricata alone is about 90% of a
   * run). None of that needs the database. Until this phase existed, all of it ran inside the
   * pipeline transaction, holding a pooled connection open and idle the whole time. An extractor
   * that splits into "run the tool on the file" and "map the output onto conversations" does the
   * first half here and returns the second half as a {@link Prepared}. The runner applies it, inside
   * the transaction, once parsing has produced the conversations.
   *
   * <p>At this point {@code target.conversations()} is <b>empty</b>, because nothing has been parsed
   * yet. Use only {@code capture()} and {@code file()}. {@link #enabledFor} is evaluated against the
   * same target, so it must not depend on the conversations either.
   *
   * <p>The default, {@code null}, means "no split". The runner then calls {@link #extract} inside the
   * transaction as before, so an extractor that never overrides this behaves exactly as it always
   * did. An exception thrown here is recorded as this extractor's FAILED outcome, and the others
   * carry on.
   */
  default Prepared prepare(ExtractionTarget target) {
    return null;
  }

  /** The second half of a {@link #prepare}d extraction: applies the tool's output to conversations. */
  @FunctionalInterface
  interface Prepared {
    /** Writes facts onto {@code conversations}, as {@link #extract} would. Never returns null. */
    Outcome applyTo(List<PcapParserService.ConversationInfo> conversations);
  }

  /**
   * What happened, for the manifest.
   *
   * <p>{@code detail} is read by a human wondering why a finding is missing — "ndpiReader not
   * installed (install libndpi-bin)" earns its place; "failed" does not.
   */
  record Outcome(ExtractionManifest.Status status, String detail) {

    public static Outcome completed(String detail) {
      return new Outcome(ExtractionManifest.Status.COMPLETED, detail);
    }

    public static Outcome failed(String detail) {
      return new Outcome(ExtractionManifest.Status.FAILED, detail);
    }

    public static Outcome skipped(String detail) {
      return new Outcome(ExtractionManifest.Status.SKIPPED, detail);
    }
  }
}
