package com.tracepcap.analysis.spi;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Read port for per-file conversation facts (#512 slices 6a/6c): the core of the fact base, served
 * without exposing the {@code analysis} module's repositories or JPA entities.
 *
 * <p><b>Why the facts are grouped rather than flat.</b> Consumers read ~24 distinct fields off a
 * conversation, and they do not read them uniformly: the timeline wants bytes over time, the tracer
 * wants endpoints, the story detectors want certificates and risks. A single 24-field record would
 * hand every consumer two dozen fields to ignore — the god-port the seam exists to prevent. Three
 * nested groups keep each consumer's surface to what it actually asked for.
 *
 * <p>The groups are the fact grades from the architecture, not an arbitrary carve-up — the
 * clustering fell out of measuring what each module already reads:
 *
 * <ul>
 *   <li>{@link FlowIdentity} — <b>MEASURED</b>. Properties of the traffic itself. Nothing asserted
 *       them; they were exhibited.
 *   <li>{@link TlsFacts} — <b>REPORTED</b>. Content a party put on the wire. The observation is
 *       measured; the content is testimony from an untrusted source and may be a lie.
 *   <li>{@link Findings} — <b>INFERRED</b>. A tool's judgment (nDPI, Suricata, signature matching),
 *       deterministic to run but heuristic, with known error modes.
 * </ul>
 *
 * A consumer that trusts a {@link TlsFacts} subject the way it trusts a {@link FlowIdentity} byte
 * count has made a category error, and the type now says so.
 *
 * <p>One record and one query, deliberately: splitting the groups into separate ports would mean
 * three round-trips over the same row to answer one question.
 */
public interface ConversationLookup {

  /**
   * What the traffic exhibited. Every field is a {@code NOT NULL} column except the ports, which are
   * absent for protocols that have none (ICMP, ARP) — about a quarter of rows in practice, so
   * consumers must expect them.
   */
  record FlowIdentity(
      String srcIp,
      Integer srcPort,
      String dstIp,
      Integer dstPort,
      String protocol,
      long packetCount,
      long totalBytes,
      LocalDateTime startTime,
      LocalDateTime endTime) {}

  /**
   * What a party claimed on the wire — testimony, not measurement. Every field is nullable: absent
   * for non-TLS traffic, and unverified even when present.
   *
   * <p>{@code hostname} is grouped here rather than with the flow on purpose: it comes from SNI or a
   * DNS answer, both of which a host asserts and can forge.
   */
  record TlsFacts(
      String hostname,
      String tlsIssuer,
      String tlsSubject,
      LocalDateTime tlsNotBefore,
      LocalDateTime tlsNotAfter,
      String ja3Client,
      String ja3Server) {}

  /**
   * What a tool concluded. The lists are never null (empty when the tool found nothing or did not
   * run) and are immutable — the underlying columns are Postgres arrays, and a consumer must not be
   * able to corrupt the fact base by writing through a returned reference.
   *
   * <p>Empty is ambiguous at this layer by design: "the scanner ran and found nothing" and "the
   * scanner never ran" look identical here. Consumers that must tell the two apart ask {@link
   * ExtractionManifest} — conflating them is exactly the #501 bug.
   */
  record Findings(
      String appName,
      String tsharkProtocol,
      String category,
      List<String> flowRisks,
      List<String> suricataAlerts,
      List<String> customSignatures,
      List<String> httpUserAgents) {}

  /**
   * One conversation's facts, grouped by grade. The three groups are never null — a conversation
   * with no TLS carries a {@link TlsFacts} of all-nulls rather than a null group, so consumers never
   * null-check the group itself.
   *
   * <p>{@code fileId} is carried on the record rather than left to be walked to via an association:
   * a consumer holding one conversation frequently needs its file to ask a follow-up question, and
   * making that a field keeps it from being a lazy-load that only works inside a transaction.
   */
  record ConversationFacts(UUID id, UUID fileId, FlowIdentity flow, TlsFacts tls, Findings findings) {}

  /** Every conversation in the file. Never contains null elements. */
  List<ConversationFacts> conversationFacts(UUID fileId);

  /**
   * One conversation by its own id, or empty when no such conversation exists.
   *
   * <p>No {@code fileId} parameter: a conversation id is globally unique, and callers that hold one
   * (a drill-down from a link, say) have no file in hand to pass. The returned record carries its
   * {@code fileId} so a follow-up question can be asked.
   */
  Optional<ConversationFacts> conversationFactsById(UUID conversationId);

  /**
   * Every conversation in the file where {@code ip} is either endpoint — initiator or peer.
   *
   * <p><b>Ordered by packet count, descending.</b> That ordering is part of the contract, not an
   * incidental of the query: consumers rank peers by volume and rely on it.
   */
  List<ConversationFacts> conversationFactsForIp(UUID fileId, String ip);

  /**
   * The named conversations, for a caller that already holds their ids — typically because it just
   * caused them to be written. Ids with no matching row are skipped, so the result may be shorter
   * than the input; an empty or null input yields an empty list rather than loading everything.
   */
  List<ConversationFacts> conversationFactsByIds(Collection<UUID> conversationIds);
}
