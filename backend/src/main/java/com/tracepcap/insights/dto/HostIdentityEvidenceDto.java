package com.tracepcap.insights.dto;

import java.util.List;
import java.util.Map;
import lombok.Builder;
import lombok.Value;

/**
 * The full explainable-classification payload for one host in one file (#556 follow-up).
 *
 * <p>Composes the adjudicated identity (the verdict) with the measured evidence axes (the facts that
 * fed the vote), so any host-inspection surface — the network-graph node, the conversation host
 * click, the monitor drift panels — can render the same "verdict, and why" experience from just a
 * {@code fileId + ip}. Before this, that experience lived only in the network graph, which had the
 * axis facts because it derived them frontend-side from the conversation list; a bare IP had no way
 * to obtain them.
 *
 * <p>Grades, deliberately kept distinct (mirrors the SPI split):
 *
 * <ul>
 *   <li><b>Verdict</b> — {@code primaryLabel}/{@code basis}/{@code confidence}/{@code contested}/
 *       {@code candidates}: the adjudicated identity and its per-candidate "why" breakdown.
 *   <li><b>Hardware facts</b> — {@code manufacturer}, {@code ttl}: physical fingerprint.
 *   <li><b>Service facts</b> — {@code serviceRoles} (confirmed roles) and {@code ndpiApps} (apps nDPI
 *       identified in the host's traffic).
 *   <li><b>Behaviour facts</b> — {@code initiatedConversations}/{@code answeredConversations}:
 *       measured from who opened each connection (#496). These are direction-gated: when nDPI could
 *       not measure who opened a flow, both stay 0. {@code conversationCount}/{@code peerCount} are
 *       the same behaviour axis counted <em>without</em> that gate — they are the raw fan-out the
 *       classifier's traffic-pattern signal actually weighs (≥15 peers → router), so the panel can
 *       show real evidence even on a capture where direction was never measured.
 * </ul>
 *
 * The axes carry facts only — scores belong to {@code candidates}, never to a fact (#499).
 */
@Value
@Builder
public class HostIdentityEvidenceDto {
  String ip;

  // ── Verdict (adjudicated identity) ──────────────────────────────────────────
  /** The one answer to "what is this host?" — a device type, or the human's label verbatim. */
  String primaryLabel;
  /** HUMAN (confirmed node-role/override label) or MACHINE (classification vote). */
  String basis;
  int confidence;
  /** True when machine candidates were too close to call; render the contest, not the winner. */
  boolean contested;
  /** Competing candidates when contested; each is {@code {label, source, score, reasons[]}}. */
  List<Map<String, Object>> candidates;

  // ── Hardware facts ──────────────────────────────────────────────────────────
  String manufacturer;
  Integer ttl;

  // ── Service facts ───────────────────────────────────────────────────────────
  /** Confirmed service roles (e.g. ["dns"]); never null, may be empty. */
  List<String> serviceRoles;
  /** nDPI application names identified in this host's traffic; never null, may be empty. */
  List<String> ndpiApps;

  // ── Behaviour facts (#496) ──────────────────────────────────────────────────
  /** Connections this host opened (sent SYN without ACK). */
  int initiatedConversations;
  /** Connections opened by peers that this host answered. */
  int answeredConversations;
  /** Total conversations this host took part in, regardless of measured direction. */
  int conversationCount;
  /** Distinct peers this host talked to — the fan-out the router signal keys on. */
  int peerCount;

  // ── Geolocation (external hosts only) ───────────────────────────────────────
  // From the persisted GeoIP cache (offline MMDB or ipinfo, per the offline requirement). All null
  // for private/internal IPs, which are never geolocated — the panel omits the whole block then.
  /** Country name, e.g. "United States". */
  String country;
  /** ISO country code, e.g. "US" — drives the flag emoji. */
  String countryCode;
  /** Autonomous-system number, e.g. "AS8075" (ipinfo only; null under the offline MMDB). */
  String asn;
  /** Owning organisation, e.g. "Microsoft Corporation". */
  String org;
  /** Which resolver produced this — "ipinfo" (online) or "mmdb" (offline DB). */
  String geoSource;
}
