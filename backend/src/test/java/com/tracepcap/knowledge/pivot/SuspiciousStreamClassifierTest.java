package com.tracepcap.knowledge.pivot;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.spi.PacketLookup;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.EntityType;
import com.tracepcap.knowledge.spi.Finding;
import com.tracepcap.knowledge.spi.Grade;
import com.tracepcap.knowledge.spi.Relationship;
import com.tracepcap.knowledge.spi.Severity;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class SuspiciousStreamClassifierTest {

  private static final UUID CONV = UUID.randomUUID();
  private static final EntityRef HOST = EntityRef.host("172.16.1.66");
  private static final EntityRef EXT = EntityRef.external("141.98.10.79");

  @Mock private PacketLookup packetLookup;

  /** A board holding one suspected-beacon finding pointing at conversation CONV, not yet classified. */
  private CaseKnowledge boardWithBeacon() {
    CaseKnowledgeBuilder b = new CaseKnowledgeBuilder(UUID.randomUUID());
    b.addRelationship(Relationship.of(HOST, "communicates-with", EXT, Grade.MEASURED, "beacon"));
    b.addFinding(new Finding("suspected-beacon", "beacon shape", Severity.HIGH, Grade.INFERRED,
        "beacon", List.of(HOST, EXT), List.of(CONV.toString()), null));
    return b.build();
  }

  private CaseKnowledge pivot(CaseKnowledge board) {
    CaseKnowledgeBuilder out = new CaseKnowledgeBuilder(board.fileId()).addAll(board);
    new SuspiciousStreamClassifier(packetLookup).pivot(board, out);
    return out.build();
  }

  private static String hex(String s) {
    StringBuilder sb = new StringBuilder();
    for (byte b : s.getBytes(StandardCharsets.UTF_8)) sb.append(String.format("%02x", b));
    return sb.toString();
  }

  @Test
  void namesStrratFromTheCleartextCheckin() {
    when(packetLookup.payloadsInConversation(CONV)).thenReturn(List.of(hex(
        "ping|STRRAT|1BE8292C|DESKTOP-SKBR25F|ccollier|Microsoft Windows 11 Pro|64-bit|Windows Defender||1.6|US:United States|Not Installed|1 Sec")));

    CaseKnowledge k = pivot(boardWithBeacon());

    assertThat(k.entitiesOfType(EntityType.MALWARE)).singleElement()
        .satisfies(e -> assertThat(e.key()).isEqualTo("STRRAT"));
    assertThat(k.relationshipsWithPredicate("c2-of")).singleElement().satisfies(r -> {
      assertThat(r.from()).isEqualTo(EXT);
      assertThat(r.to()).isEqualTo(EntityRef.malware("STRRAT"));
    });
  }

  @Test
  void theConclusionCarriesItsEvidence_aFindingCitingTheBeaconConversation() {
    when(packetLookup.payloadsInConversation(CONV)).thenReturn(List.of(hex("ping|STRRAT|1BE8292C|HOST|user|Win")));

    CaseKnowledge k = pivot(boardWithBeacon());

    assertThat(k.findingsOfCategory("c2-classification")).singleElement().satisfies(f -> {
      assertThat(f.summary()).contains("STRRAT").contains("141.98.10.79").contains("cleartext");
      assertThat(f.concerns()).contains(EXT, EntityRef.malware("STRRAT"));
      assertThat(f.evidence()).containsExactly(CONV.toString()); // cites the stream it read
    });
  }

  @Test
  void leavesAnUnrecognizedStreamUnattributed() {
    when(packetLookup.payloadsInConversation(CONV))
        .thenReturn(List.of(hex("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")));

    CaseKnowledge k = pivot(boardWithBeacon());

    assertThat(k.entitiesOfType(EntityType.MALWARE)).isEmpty();
    assertThat(k.relationshipsWithPredicate("c2-of")).isEmpty();
  }

  @Test
  void appliesToWhileAnUnclassifiedBeaconRemains_thenStops() {
    SuspiciousStreamClassifier classifier = new SuspiciousStreamClassifier(packetLookup);
    assertThat(classifier.appliesTo(boardWithBeacon())).isTrue();

    // once the external carries a c2-of edge, the pivot has nothing left to do
    CaseKnowledgeBuilder done = new CaseKnowledgeBuilder(UUID.randomUUID()).addAll(boardWithBeacon());
    done.addRelationship(Relationship.of(EXT, "c2-of", EntityRef.malware("STRRAT"), Grade.INFERRED, "x"));
    assertThat(classifier.appliesTo(done.build())).isFalse();
  }
}
