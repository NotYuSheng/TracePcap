package com.tracepcap.knowledge.pivot;

import com.tracepcap.analysis.spi.PacketLookup;
import com.tracepcap.common.TsharkHexUtil;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.EntityType;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.InvestigativePivot;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.Severity;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/**
 * Follows a {@link com.tracepcap.knowledge.contributor.BeaconContributor suspected beacon}, reads the
 * conversation's stream, and names the malware family from its command-and-control protocol — with
 * <b>no IDS signature involved</b> (#819, L2). This is the pivot that proves the thesis: STRRAT
 * beacons a cleartext, pipe-delimited check-in ({@code ping|STRRAT|<id>|<host>|<user>|<os>|…}) that
 * self-identifies, and following the stream recovers the family, the C2, and (via the host that
 * contacted it) the victim, whether or not Suricata has a rule.
 *
 * <p>Parse is not interpretation: the payload bytes come from {@link PacketLookup} (Extract already
 * captured them); this pivot only <em>reads</em> them and matches them against a registry of known
 * C2-protocol fingerprints. The registry is the extensible surface — a new family is one entry, and
 * a stream that matches nothing is left as a suspected beacon (honestly unattributed), never guessed.
 */
@Component
@RequiredArgsConstructor
public class SuspiciousStreamClassifier implements InvestigativePivot {

  private static final String SUSPECTED_BEACON = "suspected-beacon";
  private static final String C2_OF = "c2-of";
  private static final String C2_CLASSIFICATION = "c2-classification";
  /** How much of a stream's opening is read — a fingerprint sits in the first few packets. */
  private static final int MAX_PAYLOADS_READ = 64;
  private static final int MAX_BYTES_PER_PAYLOAD = 512;
  /** Beacons followed per pass; each is a DB read, and this runs on user-facing requests. */
  private static final int MAX_BEACONS_PER_PASS = 8;

  /**
   * Known C2-protocol fingerprints, matched against the decoded stream. Each is a family plus a
   * pattern specific enough that a benign stream will not trip it. <b>This is the playbook:</b> add a
   * family by adding a row — many commodity RATs self-identify in a delimited check-in.
   */
  private record Fingerprint(String family, Pattern pattern) {}

  private static final List<Fingerprint> FINGERPRINTS =
      List.of(
          // STRRAT: pipe-delimited beacon whose second field is the family name.
          new Fingerprint("STRRAT", Pattern.compile("(?i)(?:^|\\|)\\s*strrat\\s*\\|")));

  private final PacketLookup packetLookup;

  @Override
  public String name() {
    return "stream-classifier";
  }

  @Override
  public boolean appliesTo(CaseKnowledge board) {
    Set<EntityRef> alreadyC2 = classifiedExternals(board);
    return board.findingsOfCategory(SUSPECTED_BEACON).stream()
        .anyMatch(f -> externalOf(f).map(ext -> !alreadyC2.contains(ext)).orElse(false));
  }

  @Override
  public void pivot(CaseKnowledge board, CaseKnowledgeBuilder out) {
    // Externals already classified — from earlier rounds AND from this pass, so several beacons to
    // one C2 (different source ports) classify it once rather than posting duplicate edges/findings.
    Set<EntityRef> classified = new HashSet<>(classifiedExternals(board));
    int followed = 0;
    for (Finding beacon : board.findingsOfCategory(SUSPECTED_BEACON)) {
      Optional<EntityRef> external = externalOf(beacon);
      if (external.isEmpty() || classified.contains(external.get())) continue; // idempotent
      if (beacon.evidence().isEmpty()) continue;
      // Bound the work one request can trigger: each followed beacon is a DB read.
      if (followed++ >= MAX_BEACONS_PER_PASS) break;

      String stream = readOpening(beacon.evidence().get(0));
      if (stream == null) continue;
      for (Fingerprint fp : FINGERPRINTS) {
        if (fp.pattern().matcher(stream).find()) {
          classified.add(external.get());
          EntityRef malware = EntityRef.malware(fp.family());
          out.addEntity(malware);
          out.addRelationship(Relationship.of(external.get(), C2_OF, malware, Grade.INFERRED, name()));
          // The conclusion must carry its evidence: without this the C2/malware answers have no
          // basis, and anything reading them (the panel, the narrative) cannot say *why* — it would
          // even claim the payloads were unavailable when this stage read them.
          out.addFinding(
              new Finding(
                  C2_CLASSIFICATION,
                  fp.family() + " C2 identified from the beacon's cleartext check-in (matched the "
                      + fp.family() + " protocol fingerprint in the stream to " + external.get().key() + ")",
                  Severity.HIGH,
                  Grade.INFERRED,
                  name(),
                  List.of(external.get(), malware),
                  beacon.evidence(),
                  Map.of("family", fp.family(), "method", "stream-fingerprint")));
          break; // one family per beacon
        }
      }
    }
  }

  /** The externals already marked as a C2 on the board — so we never re-classify one. */
  private static Set<EntityRef> classifiedExternals(CaseKnowledge board) {
    return board.relationshipsWithPredicate(C2_OF).stream()
        .map(Relationship::from)
        .collect(Collectors.toSet());
  }

  /** The external endpoint a suspected-beacon finding concerns. */
  private static Optional<EntityRef> externalOf(Finding beacon) {
    return beacon.concerns().stream()
        .filter(ref -> ref.type() == EntityType.EXTERNAL_SERVICE)
        .findFirst();
  }

  /**
   * Reads how the conversation's stream <em>opens</em> — its first few payloads, hex → printable
   * ASCII. Bounded at the query (a LIMIT), not after the fact: a check-in fingerprint is in the
   * opening of a stream, and materialising every payload of a long-lived flow would be an OOM risk
   * for no gain.
   */
  private String readOpening(String conversationId) {
    UUID convId;
    try {
      convId = UUID.fromString(conversationId);
    } catch (IllegalArgumentException e) {
      return null;
    }
    StringBuilder sb = new StringBuilder();
    for (String hex : packetLookup.firstPayloadsInConversation(convId, MAX_PAYLOADS_READ)) {
      if (hex == null) continue;
      sb.append(TsharkHexUtil.toAscii(hex, MAX_BYTES_PER_PAYLOAD)).append('\n');
    }
    return sb.toString();
  }
}
