package com.tracepcap.analysis.spi;

import com.tracepcap.analysis.dto.ConversationFilterParams;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Map;
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
   * consumers must expect them — and the initiator pair.
   *
   * <p><b>{@code srcIp} is not "the client".</b> Conversation keys are normalised so A→B and B→A
   * share one row, so srcIp is whichever endpoint sorted first. To ask who opened the connection,
   * use {@code initiatorIp}: the endpoint that sent SYN without ACK (#496).
   *
   * <p>{@code initiatorIp} is null when <em>unknown</em> — UDP, ICMP and ARP have no handshake, and
   * a capture can begin mid-flow and miss the SYN. Null never means "nobody initiated", and it must
   * not be backfilled by guessing from port numbers: a server on :4434 is still a server, and
   * treating the lower port as the listener is exactly the bug this field replaces.
   */
  record FlowIdentity(
      String srcIp,
      Integer srcPort,
      String dstIp,
      Integer dstPort,
      String initiatorIp,
      Integer initiatorPort,
      String protocol,
      long packetCount,
      long totalBytes,
      LocalDateTime startTime,
      LocalDateTime endTime,
      String srcMac,
      String dstMac,
      String connectionOutcome,
      String transport,
      Long bytesSrcToDst,
      Long bytesDstToSrc) {

    /** Without the transport and per-direction bytes: unknown (captures analysed before them). */
    public FlowIdentity(
        String srcIp, Integer srcPort, String dstIp, Integer dstPort, String initiatorIp,
        Integer initiatorPort, String protocol, long packetCount, long totalBytes,
        LocalDateTime startTime, LocalDateTime endTime, String srcMac, String dstMac,
        String connectionOutcome) {
      this(srcIp, srcPort, dstIp, dstPort, initiatorIp, initiatorPort, protocol, packetCount,
          totalBytes, startTime, endTime, srcMac, dstMac, connectionOutcome, null, null, null);
    }

    /** Without per-direction bytes: unknown (captures analysed before they were kept). */
    public FlowIdentity(
        String srcIp, Integer srcPort, String dstIp, Integer dstPort, String initiatorIp,
        Integer initiatorPort, String protocol, long packetCount, long totalBytes,
        LocalDateTime startTime, LocalDateTime endTime, String srcMac, String dstMac,
        String connectionOutcome, String transport) {
      this(srcIp, srcPort, dstIp, dstPort, initiatorIp, initiatorPort, protocol, packetCount,
          totalBytes, startTime, endTime, srcMac, dstMac, connectionOutcome, transport, null, null);
    }

    /** Bytes {@code ip} sent in this flow, or null when unknown. */
    public Long bytesSentBy(String ip) {
      if (ip == null) return null;
      if (ip.equals(srcIp)) return bytesSrcToDst;
      if (ip.equals(dstIp)) return bytesDstToSrc;
      return null;
    }

    /**
     * Without the connection outcome (#1233): unknown. {@code connectionOutcome} is ANSWERED,
     * NO_ANSWER or REJECTED for TCP, null when not TCP or the SYN wasn't captured.
     */
    public FlowIdentity(
        String srcIp, Integer srcPort, String dstIp, Integer dstPort, String initiatorIp,
        Integer initiatorPort, String protocol, long packetCount, long totalBytes,
        LocalDateTime startTime, LocalDateTime endTime, String srcMac, String dstMac) {
      this(srcIp, srcPort, dstIp, dstPort, initiatorIp, initiatorPort, protocol, packetCount,
          totalBytes, startTime, endTime, srcMac, dstMac, null);
    }

    /** Without each side's MAC (#462): they default to unknown. */
    public FlowIdentity(
        String srcIp, Integer srcPort, String dstIp, Integer dstPort, String initiatorIp,
        Integer initiatorPort, String protocol, long packetCount, long totalBytes,
        LocalDateTime startTime, LocalDateTime endTime) {
      this(srcIp, srcPort, dstIp, dstPort, initiatorIp, initiatorPort, protocol, packetCount,
          totalBytes, startTime, endTime, null, null, null);
    }

    /** The MAC on {@code ip}'s side of the flow, when recorded (#462). */
    public String macOf(String ip) {
      if (ip == null) return null;
      return ip.equals(srcIp) ? srcMac : ip.equals(dstIp) ? dstMac : null;
    }
  }

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
      String ja3Server,
      String ja4Client,
      String tlsVersion,
      CertFacts cert) {

    /** Without the certificate's detail (#1235): unknown. */
    public TlsFacts(
        String hostname, String tlsIssuer, String tlsSubject, LocalDateTime tlsNotBefore,
        LocalDateTime tlsNotAfter, String ja3Client, String ja3Server, String ja4Client,
        String tlsVersion) {
      this(hostname, tlsIssuer, tlsSubject, tlsNotBefore, tlsNotAfter, ja3Client, ja3Server,
          ja4Client, tlsVersion, null);
    }
  }

  /**
   * The server certificate's detail (#1235), parsed from the DER Suricata logs. A description,
   * never a trust verdict: no trust store or revocation check runs offline.
   *
   * @param sans subject alternative names (DNS names and IP addresses), at most {@code TlsCertificateParser.MAX_SANS}
   * @param keyType "RSA", "EC", "DSA", or the JDK's algorithm name
   * @param keyBits the key size in bits, or null when unknown
   * @param signatureAlgorithm e.g. "SHA256withRSA"
   * @param selfSigned issuer equals subject and the certificate verifies with its own key
   * @param chainLength certificates the server sent, the leaf included
   */
  record CertFacts(
      List<String> sans,
      String keyType,
      Integer keyBits,
      String signatureAlgorithm,
      boolean selfSigned,
      int chainLength) {

    /** RSA/DSA keys below this many bits are weak (NIST SP 800-131A: 2048 since 2014). */
    public static final int MIN_RSA_BITS = 2048;

    /** EC keys below this many bits are weak (P-224 and below). */
    public static final int MIN_EC_BITS = 256;

    /** A key too short to trust: RSA/DSA under 2048 bits, EC under 256. */
    public boolean weakKey() {
      if (keyBits == null || keyType == null) return false;
      return "EC".equals(keyType) ? keyBits < MIN_EC_BITS : keyBits < MIN_RSA_BITS;
    }

    /** Signed with MD5 or SHA-1, which can be forged. */
    public boolean weakSignature() {
      if (signatureAlgorithm == null) return false;
      String s = signatureAlgorithm.toUpperCase(java.util.Locale.ROOT);
      return s.startsWith("MD5") || s.startsWith("MD2") || s.startsWith("SHA1");
    }

    /**
     * Whether the certificate covers {@code serverName}: an exact SAN, or a single-label wildcard
     * ({@code *.example.com} covers {@code www.example.com}, not {@code a.b.example.com}). Null
     * when it can't be judged: no name to check, or no SANs listed.
     */
    public Boolean covers(String serverName) {
      if (serverName == null || serverName.isBlank() || sans == null || sans.isEmpty()) return null;
      String name = serverName.trim().toLowerCase(java.util.Locale.ROOT);
      if (name.endsWith(".")) name = name.substring(0, name.length() - 1);
      for (String san : sans) {
        String s = san.toLowerCase(java.util.Locale.ROOT);
        if (s.equals(name)) return true;
        if (s.startsWith("*.")) {
          String suffix = s.substring(1);
          int dot = name.indexOf('.');
          if (dot > 0 && name.substring(dot).equals(suffix)) return true;
        }
      }
      return false;
    }
  }


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

  /**
   * How many of a file's conversations carry each value of every filter facet — the counts beside
   * the filter chips. Whole-file counts, not narrowed by any active filter. Keys are the values the
   * filters take, except L7 protocols, which are upper-cased (their stored spelling varies).
   */
  record FacetCounts(
      Map<String, Long> protocols,
      Map<String, Long> l7Protocols,
      Map<String, Long> apps,
      Map<String, Long> categories,
      Map<String, Long> fileTypes,
      Map<String, Long> riskTypes,
      Map<String, Long> customSignatures,
      Map<String, Long> suricataAlerts,
      Map<String, Long> countries,
      Map<String, Long> deviceTypes,
      Map<String, Long> outcomes) {}

  /** Per-value conversation counts for every filter facet, aggregated in the database. */
  FacetCounts facetCounts(UUID fileId);

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
   * How many captures and conversations each nDPI application name appears in, across the install.
   * Counts original captures only: a re-analysis is a copy, and would count the same traffic twice.
   */
  record AppUsage(String appName, long captures, long conversations) {}

  List<AppUsage> appUsage();

  /** The captures (originals) an nDPI application name appears in, most conversations first. */
  record AppCapture(UUID fileId, String fileName, long conversations) {}

  List<AppCapture> appCaptures(String appName, int limit);

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
  /**
   * Distinct security-signal count per file — custom signatures, Suricata alerts and detected file
   * types, counted once each per file.
   *
   * <p>Batched over several files because the monitor renders a column of snapshots at once and the
   * per-file version of this was N queries. Files with no signals are absent from the map rather
   * than present with zero, so callers must supply their own default.
   */
  Map<UUID, Long> securitySignalCounts(Collection<UUID> fileIds);

  /**
   * The distinct stored custom-rule names (global and capture rules) per file, batched. Lets a
   * network's view adjust {@link #securitySignalCounts} for the global rules it suppresses (#925).
   * Files with none are absent.
   */
  Map<UUID, java.util.Set<String>> customSignatureNames(Collection<UUID> fileIds);

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

  /**
   * Conversations between one pair of hosts, and which side opened them: the address mix a
   * capture's vantage point is read from (docs/architecture/investigation-framework.rst, "Capture
   * context"). {@code a} and {@code b} are as stored (srcIp, dstIp); the rest, where the opener
   * isn't known (UDP, ICMP, a connection already open when the capture began), is neither.
   */
  record HostPair(String a, String b, long conversations, long openedByA, long openedByB) {}

  /** Every pair of hosts with a conversation, aggregated in the database. */
  List<HostPair> hostPairs(UUID fileId);

  /**
   * The distinct ports {@code ip} answered on: the responder's port of each conversation another
   * host opened to it. Many ports from many openers is a sensor's shape; a server answers a few.
   */
  long distinctAnsweredPorts(UUID fileId, String ip);

  /**
   * How one host's conversations were opened, counted in the database: {@code opened} by it,
   * {@code answered} (opened to it by another host), from how many distinct {@code openers}, and on
   * how many distinct {@code answeredPorts}. Conversations with no known opener count in none.
   */
  record HostOpenings(long opened, long answered, long openers, long answeredPorts) {}

  /** {@link HostOpenings} for one host, without reading every host pair. */
  HostOpenings hostOpenings(UUID fileId, String ip);

  /** {@code conversations} that {@code opener} opened to {@code target}. */
  record Opening(String opener, String target, long conversations) {}

  /**
   * Who opened conversations to any of {@code targets}, per opener and target, aggregated in the
   * database: the target is the side that didn't open it, so a target's own outbound
   * conversations aren't here (one target opening to another is). Only conversations with a known
   * opener; none for an empty {@code targets}.
   */
  List<Opening> openingsTo(UUID fileId, Collection<String> targets);

  /**
   * A certificate one server presented on a port. The server is the side that didn't open the
   * conversation, or the destination when nobody knows who opened it.
   */
  record ServerCertificate(String server, Integer port, String subject, String issuer) {}

  /**
   * Each distinct certificate a server presented, without loading the TLS conversations: the same
   * rows {@link #tlsConversations(UUID)} reads (an issuer recorded).
   */
  List<ServerCertificate> serverCertificates(UUID fileId);

  /** {@link #serverCertificates(UUID)} for one server. */
  List<ServerCertificate> serverCertificates(UUID fileId, String server);

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
    /**
     * tshark's application-layer protocol names ({@code TLS}, {@code SMB2}), upper case, as the
     * Conversations L7 filter takes them. MEASURED.
     */
    PROTOCOL,
    /** HTTP User-Agent strings clients sent. REPORTED — a client says what it likes. */
    HTTP_USER_AGENT
  }
}
