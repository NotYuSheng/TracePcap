package com.tracepcap.analysis.spi;

import com.tracepcap.analysis.dto.ConversationFilterParams;
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
   * The conversations in a file matching {@code filter}, or all of them when {@code filter} is null
   * or has no active criteria.
   *
   * <p>Takes the filter rather than a query: {@link ConversationFilterParams} already sits on the
   * seam, so a consumer can say <em>what</em> it wants without knowing <em>how</em> the rows are
   * selected. The JPA {@code Specification} that implements this stays inside {@code analysis} —
   * exposing it would put {@code ConversationEntity} in the caller's signature and re-open the seam
   * through the type system, which is exactly how the filtered paths bypassed it before.
   */
  List<ConversationFacts> conversationFacts(UUID fileId, ConversationFilterParams filter);

  /** One page of conversations plus the unpaged total, so a caller can report "N of M". */
  record ConversationPage(List<ConversationFacts> content, long totalElements) {}

  /**
   * One page of the conversations matching {@code filter}, sorted by the filter's own
   * {@code sortBy}/{@code sortDir}.
   *
   * <p>{@code page} is <b>1-indexed</b>, matching the REST convention rather than Spring's 0-indexed
   * {@code Pageable} — callers on this side of the seam should not have to know which one they're
   * talking to.
   *
   * <p>Sorting is resolved here rather than by the caller. {@code sortBy} names a field of the
   * <em>API</em> ("bytes", "packets", "duration"); mapping those onto columns is schema knowledge,
   * and a feature module doing that mapping itself is reaching through the seam with a string
   * instead of a type. An unrecognised {@code sortBy} yields an unsorted page rather than an error.
   */
  ConversationPage conversationPage(
      UUID fileId, int page, int pageSize, ConversationFilterParams filter);

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

  /**
   * The distinct values of one facet across a whole file — the vocabulary the file exhibits, not the
   * per-conversation detail.
   *
   * <p>Separate from {@link #conversationFacts} because the question differs and so does the cost:
   * comparing two snapshots asks "which alert types appeared or disappeared", which the database
   * answers with a DISTINCT over an array column. Deriving it by loading every conversation and
   * folding in Java would pull thousands of rows to build a set of a dozen strings.
   *
   * <p>Values are never null or blank.
   */
  List<String> distinctValues(UUID fileId, Facet facet);

  /**
   * The vocabularies a file can be asked for — the distinct values of one column across every
   * conversation. Used to populate filter dropdowns and to diff one snapshot against another.
   *
   * <p>Grades differ within this enum, which is why it is named for the shape of the question rather
   * than for findings: {@link #IP} and {@link #PROTOCOL} are MEASURED, while the rest are INFERRED —
   * a tool's conclusion. For the inferred ones, an empty result means "nothing concluded", which is
   * not the same as "nothing there"; ask {@link ExtractionManifest} to tell those apart.
   */
  enum Facet {
    /** Suricata rule names that fired. INFERRED. */
    SURICATA_ALERT,
    /** User-defined signature names that matched. INFERRED. */
    CUSTOM_SIGNATURE,
    /** nDPI flow-risk labels. INFERRED. */
    RISK_TYPE,
    /** File types carvers detected in packet payloads. INFERRED. */
    FILE_TYPE,
    /** nDPI application names. INFERRED. */
    APP_NAME,
    /** Every IP seen as either endpoint. MEASURED. */
    IP,
    /** Transport protocols observed. MEASURED. */
    PROTOCOL
  }
}
