package com.tracepcap.knowledge.pivot;

import com.tracepcap.analysis.spi.PacketLookup;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.EntityType;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.InvestigativePivot;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.Severity;
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
  /** Bound the decode so a chatty conversation can't blow up heap (#779 line of work). */
  private static final int MAX_DECODED_CHARS = 64 * 1024;

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
    Set<EntityRef> alreadyC2 = classifiedExternals(board);
    for (Finding beacon : board.findingsOfCategory(SUSPECTED_BEACON)) {
      Optional<EntityRef> external = externalOf(beacon);
      if (external.isEmpty() || alreadyC2.contains(external.get())) continue; // idempotent
      if (beacon.evidence().isEmpty()) continue;

      String stream = decode(beacon.evidence().get(0));
      if (stream == null) continue;
      for (Fingerprint fp : FINGERPRINTS) {
        if (fp.pattern().matcher(stream).find()) {
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

  /** Reads and decodes the conversation's payloads (hex → printable ASCII), bounded. */
  private String decode(String conversationId) {
    UUID convId;
    try {
      convId = UUID.fromString(conversationId);
    } catch (IllegalArgumentException e) {
      return null;
    }
    StringBuilder sb = new StringBuilder();
    for (String hex : packetLookup.payloadsInConversation(convId)) {
      if (hex == null) continue;
      String clean = hex.replaceAll("[^0-9a-fA-F]", "");
      for (int i = 0; i + 1 < clean.length() && sb.length() < MAX_DECODED_CHARS; i += 2) {
        int b = Integer.parseInt(clean.substring(i, i + 2), 16);
        sb.append(b >= 0x20 && b < 0x7f ? (char) b : '.');
      }
      sb.append('\n');
      if (sb.length() >= MAX_DECODED_CHARS) break;
    }
    return sb.toString();
  }
}
