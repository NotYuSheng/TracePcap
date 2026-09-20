package com.tracepcap.knowledge.contributor;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.ConversationLookup.FlowIdentity;
import com.tracepcap.analysis.spi.ConversationLookup.TlsFacts;
import com.tracepcap.common.net.IpLocality;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.KnowledgeContributor;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.Severity;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Flags the <em>shape</em> of a C2 beacon from traffic facts alone — no IDS signature required
 * (#819). The founding motivation of the knowledge layer is that a conclusion must not depend on a
 * particular library being present: STRRAT is obvious once Suricata has a rule for it, but the same
 * host would beacon whether or not a rule exists. This contributor posts a {@code suspected-beacon}
 * finding when a host holds a sustained, low-throughput, raw-TCP session to an external endpoint on a
 * non-standard port — the wire shape of a command channel. It never names a family or asserts a C2;
 * it hands the {@link SuspiciousStreamClassifier} a conversation worth following.
 *
 * <p>Deliberately conservative to keep the false-positive rate low (the point of a deterministic
 * check over the LLM's volume-based guessing): TLS sessions are excluded (a real beacon on a raw port
 * carries no SNI/JA3), so are flows nDPI recognised as a known application, ordinary service ports
 * and bulk transfers, and the local host must have opened the connection where that is known. Periodicity — the strongest beacon signal — needs
 * per-packet timing this port does not yet expose; until then this is a suspicion, graded INFERRED,
 * for confirmation downstream, not an assertion.
 */
@Component
@RequiredArgsConstructor
public class BeaconContributor implements KnowledgeContributor {

  static final String SUSPECTED_BEACON = "suspected-beacon";
  static final String COMMUNICATES_WITH = "communicates-with";

  /** Sustained: a beacon checks in many times, unlike a one-shot connection. */
  private static final long MIN_PACKETS = 30;
  private static final long MIN_DURATION_SECONDS = 20;
  /** Low-throughput: control traffic, not a bulk transfer (that is the traffic/data-transfer path). */
  private static final long MAX_AVG_BYTES_PER_PACKET = 800;

  /** A session to a standard service port is ordinary, not a covert channel. */
  private static final Set<Integer> WELL_KNOWN_PORTS =
      Set.of(20, 21, 22, 23, 25, 53, 67, 68, 80, 88, 110, 123, 135, 137, 138, 139, 143, 161, 162,
          389, 443, 445, 465, 587, 636, 993, 995, 1900, 2049, 3268, 3269, 3389, 5353, 5985, 5986,
          8080, 8443);

  private final ConversationLookup conversationLookup;

  @Override
  public String name() {
    return "beacon";
  }

  @Override
  public void contribute(UUID fileId, CaseKnowledgeBuilder board) {
    for (ConversationFacts conv : conversationLookup.conversationFacts(fileId)) {
      FlowIdentity f = conv.flow();
      if (f.protocol() == null || !"TCP".equalsIgnoreCase(f.protocol())) continue;
      if (f.srcIp() == null || f.dstIp() == null) continue;

      boolean srcLocal = IpLocality.isLocal(f.srcIp());
      boolean dstLocal = IpLocality.isLocal(f.dstIp());
      if (srcLocal == dstLocal) continue; // need exactly one internal ↔ one external endpoint

      String hostIp = srcLocal ? f.srcIp() : f.dstIp();
      String extIp = srcLocal ? f.dstIp() : f.srcIp();
      Integer extPort = srcLocal ? f.dstPort() : f.srcPort();

      if (isTls(conv.tls())) continue;                                  // raw beacon carries no TLS
      // A protocol nDPI recognised (SSH on 2222, MySQL, Redis, XMPP, a VPN…) is a known service on
      // an unusual port, not an unexplained channel. Only flows nDPI could not name are suspect.
      if (!isUnidentified(conv.findings() == null ? null : conv.findings().appName())) continue;
      if (extPort == null || WELL_KNOWN_PORTS.contains(extPort)) continue; // ordinary service
      if (f.initiatorIp() != null && !f.initiatorIp().equals(hostIp)) continue; // outbound only

      long packets = f.packetCount();
      long durationSec = durationSeconds(f);
      long avgBytes = packets > 0 ? f.totalBytes() / packets : 0;
      if (packets < MIN_PACKETS || durationSec < MIN_DURATION_SECONDS) continue; // not sustained
      if (avgBytes > MAX_AVG_BYTES_PER_PACKET) continue;                          // bulk, not control

      EntityRef host = EntityRef.host(hostIp);
      EntityRef external = EntityRef.external(extIp);
      board.addEntity(external);
      board.addRelationship(Relationship.of(host, COMMUNICATES_WITH, external, Grade.MEASURED, name()));
      board.addFinding(
          new Finding(
              SUSPECTED_BEACON,
              hostIp + " → " + extIp + ":" + extPort + " — sustained low-throughput raw-TCP session ("
                  + packets + " pkts / " + durationSec + "s, ~" + avgBytes + " B/pkt), no TLS: a beacon shape",
              // MEDIUM: a shape-only suspicion. The classifier's confirmed finding is the HIGH one.
              Severity.MEDIUM,
              Grade.INFERRED,
              name(),
              List.of(host, external),
              List.of(conv.id().toString()),
              Map.of("dstPort", extPort, "packets", packets,
                  "durationSec", durationSec, "avgBytesPerPacket", avgBytes)));
    }
  }

  /**
   * nDPI leaves a flow's application blank (or "Unknown") when it could not identify it — 285 of 426
   * conversations in the STRRAT capture, including the beacon itself.
   */
  private static boolean isUnidentified(String appName) {
    return appName == null || appName.isBlank() || "unknown".equalsIgnoreCase(appName.trim());
  }

  /** A TLS session announces itself (SNI, a JA3 fingerprint, or a cert subject) — not a raw beacon. */
  private static boolean isTls(TlsFacts t) {
    return t != null && (t.hostname() != null || t.ja3Client() != null || t.tlsSubject() != null);
  }

  private static long durationSeconds(FlowIdentity f) {
    if (f.startTime() == null || f.endTime() == null) return 0;
    return Math.max(0, Duration.between(f.startTime(), f.endTime()).getSeconds());
  }
}
