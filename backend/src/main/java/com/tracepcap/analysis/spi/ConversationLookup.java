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
   * Every conversation in a file matching {@code filter}, sorted by the filter's own {@code
   * sortBy}/{@code sortDir}. A null filter means "all of them, unsorted".
   *
   * <p>Unpaged on purpose — this is the CSV-export shape, where the caller genuinely wants the whole
   * result set. For anything a user scrolls, use {@link #conversationPage}.
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

  /** One peer and the bytes exchanged with it. */
  record PeerBytes(String ip, long bytes) {}

  /**
   * Traffic totals for one application or L7 protocol within a file, plus its heaviest peers.
   *
   * <p>Counts are zero and {@code topPeers} empty when nothing matched — never null.
   */
  record EntityStats(
      long conversationCount, long packetCount, long totalBytes, List<PeerBytes> topPeers) {}

  /**
   * Totals and top peers for a single nDPI application name.
   *
   * <p>Aggregated in the database, and typed here rather than returned as the {@code Object[]} rows
   * JPA projections yield: a caller doing {@code ((Number) row[2]).longValue()} is coupled to the
   * SELECT list's column order, which is about as brittle as coupling gets.
   */
  EntityStats statsForApp(UUID fileId, String appName, int topPeerLimit);

  /**
   * Totals and top peers for a single L7 protocol.
   *
   * <p>Matching handles the protocol's stored spelling variants ("TLS", "Tls", "tls", "The Tls" —
   * nDPI and tshark disagree on casing). That expansion is storage trivia and stays behind the seam;
   * callers pass the protocol as the user names it.
   */
  EntityStats statsForL7Protocol(UUID fileId, String l7Protocol, int topPeerLimit);

  /**
   * Traffic attributed to one named thing — an app, an L7 protocol, a category.
   *
   * <p>{@code packetCount} is always populated; {@code totalBytes} is zero for breakdowns that only
   * count packets (see {@link Breakdown#CATEGORY}).
   */
  record NamedTotals(String name, long packetCount, long totalBytes) {}

  /** The ways a file's traffic can be broken down, each aggregated in the database. */
  enum Breakdown {
    /** By nDPI application name, heaviest first. Carries bytes. */
    APPLICATION,
    /** By tshark L7 protocol, heaviest first. Carries bytes. */
    L7_PROTOCOL,
    /** By nDPI category, most packets first. Packets only — {@code totalBytes} is 0. */
    CATEGORY
  }

  /**
   * A file's traffic grouped by {@code breakdown}, ordered heaviest first, aggregated in the
   * database. Rows with no name are omitted — an unnamed slice is not a breakdown a reader can act
   * on.
   */
  List<NamedTotals> breakdown(UUID fileId, Breakdown breakdown);

  /** How many conversations the file holds. */
  long conversationCount(UUID fileId);

  /**
   * How many conversations carry at least one nDPI flow risk — the same predicate as {@link
   * #atRiskConversations}, and like it, nDPI risks only.
   */
  long atRiskConversationCount(UUID fileId);

  /**
   * The {@code limit} heaviest conversations in the file, by bytes descending — the "who talked
   * most" table.
   */
  List<ConversationFacts> topConversationsByBytes(UUID fileId, int limit);

  /**
   * Up to {@code limit} conversations carrying at least one <b>nDPI flow risk</b>, most risks first.
   *
   * <p>nDPI risks only — <em>not</em> custom-signature matches or Suricata alerts, despite the name.
   * A conversation flagged by Suricata alone does not appear here. That is the query's long-standing
   * behaviour rather than a decision made in this port, and it is stated plainly because an earlier
   * draft of this javadoc claimed all three sources; a reviewer read that, believed it, and filed a
   * bug against the report for "omitting" alerts the query never selected.
   *
   * <p><b>INFERRED</b>: this is what nDPI concluded, and "at risk" inherits its error modes. A
   * conversation absent from this list is one nDPI did not flag — not one that is safe.
   */
  List<ConversationFacts> atRiskConversations(UUID fileId, int limit);

  /** Up to {@code limit} conversations that carried a TLS certificate. */
  List<ConversationFacts> tlsConversations(UUID fileId, int limit);

  /** Every conversation in the file that carried a TLS certificate. */
  List<ConversationFacts> tlsConversations(UUID fileId);

  /** Total packets across the file's conversations — summed in the database. */
  long sumPackets(UUID fileId);

  /** How many of a protocol's conversations carry a risk flag. */
  record ProtocolRisk(String protocol, long total, long atRisk) {}

  /**
   * Per-protocol conversation counts alongside how many were flagged, busiest first — the "which
   * protocols carry the trouble" matrix.
   */
  List<ProtocolRisk> protocolRiskMatrix(UUID fileId);

  /** Total bytes across the file's conversations — summed in the database. */
  long sumBytes(UUID fileId);

  /** One host and how widely it reached: distinct destinations, and flows in total. */
  record HostFanOut(String srcIp, long distinctDestinations, long totalFlows) {}

  /**
   * Hosts that reached more than a handful of distinct destinations — the candidate set for the
   * scanning / lateral-movement shape.
   *
   * <p>Aggregated in the database. A scanner could fold this out of {@link #conversationFacts}, but
   * COUNT(DISTINCT) over a table is the database's job, and doing it in Java would mean holding
   * every conversation to produce a handful of rows.
   *
   * <p>The cut-off is the query's, not the caller's: this returns <em>candidates</em>, and deciding
   * which of them is actually interesting — and at what severity — is the scanner's judgment to make.
   */
  List<HostFanOut> fanOutCandidates(UUID fileId);

  /** One host's outbound volume. */
  record HostVolume(String srcIp, long totalBytes, long flowCount) {}

  /** The heaviest senders in the file, bytes descending, capped at a sane number for a summary. */
  List<HostVolume> topSenders(UUID fileId);

  /**
   * How many conversations nDPI could not name.
   *
   * <p>Ambiguous on its own — a zero could mean "everything was identified" or "nDPI never ran".
   * Pair it with {@link ExtractionManifest} before drawing a conclusion; #501 is the bug that
   * conflation causes.
   */
  long unidentifiedAppCount(UUID fileId);

  /** How widely one nDPI risk label appears across a file. {@code riskType} is never null or blank. */
  record RiskTypeStats(
      String riskType,
      long conversationCount,
      long totalBytes,
      long distinctSourceIps,
      long distinctDestinationIps) {}

  /**
   * Each nDPI risk label in the file with its spread — how many conversations carry it, and across
   * how many distinct hosts.
   *
   * <p>Aggregated in the database, unnesting the risk array. Nothing constrains the array's
   * <em>elements</em>, so a null or blank label is storable; such rows are dropped here rather than
   * handed on, because "a risk with no name" is not a finding any consumer can render. <b>INFERRED</b>:
   * these are nDPI's conclusions, with nDPI's error modes.
   */
  List<RiskTypeStats> riskTypeStats(UUID fileId);

  /** One unusually long-lived flow. */
  record LongSession(
      String srcIp,
      String dstIp,
      Integer dstPort,
      String protocol,
      String appName,
      long durationMs,
      long totalBytes,
      long packetCount) {}

  /**
   * Flows lasting at least {@code minSeconds}, longest first.
   *
   * <p>Duration is computed in the database from the stored start/end times, which is why this is
   * not folded out of {@link #conversationFacts}: filtering on a computed value is what SQL is for.
   */
  List<LongSession> longSessions(UUID fileId, long minSeconds);

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
    PROTOCOL,
    /** HTTP User-Agent strings clients sent. REPORTED — a client says what it likes. */
    HTTP_USER_AGENT
  }
}
