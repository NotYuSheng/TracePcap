package com.tracepcap.knowledge.contributor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.spi.ConversationLookup;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.ConversationLookup.Findings;
import com.tracepcap.analysis.spi.ConversationLookup.FlowIdentity;
import com.tracepcap.analysis.spi.ConversationLookup.TlsFacts;
import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.CaseKnowledgeBuilder;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.Relationship;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TrafficContributorTest {

  private static final UUID FILE = UUID.randomUUID();

  @Mock private ConversationLookup conversationLookup;

  private ConversationFacts conv(String src, String dst, long bytes) {
    return new ConversationFacts(
        UUID.randomUUID(), FILE,
        new FlowIdentity(src, 443, dst, 443, src, 443, "TCP", 10, bytes, null, null),
        new TlsFacts(null, null, null, null, null, null, null),
        new Findings(null, null, null, List.of(), List.of(), List.of(), List.of()));
  }

  private CaseKnowledge run(ConversationFacts... convs) {
    when(conversationLookup.conversationFacts(FILE)).thenReturn(List.of(convs));
    CaseKnowledgeBuilder board = new CaseKnowledgeBuilder(FILE);
    new TrafficContributor(conversationLookup).contribute(FILE, board);
    return board.build();
  }

  @Test
  void aggregatesBytesPerHostExternalPair_andEdgeCarriesTheTotal() {
    CaseKnowledge k = run(
        conv("172.16.1.66", "199.232.196.209", 4_000_000L),
        conv("172.16.1.66", "199.232.196.209", 4_000_000L)); // same pair, two flows

    List<Relationship> edges = k.relationshipsWithPredicate("communicates-with");
    assertThat(edges).singleElement().satisfies(r -> {
      assertThat(r.from()).isEqualTo(EntityRef.host("172.16.1.66"));
      assertThat(r.to()).isEqualTo(EntityRef.external("199.232.196.209"));
      assertThat(r.attributes()).containsEntry("bytes", 8_000_000L);
    });
  }

  @Test
  void belowThresholdPairsAreNotEdges() {
    CaseKnowledge k = run(conv("172.16.1.66", "8.8.8.8", 50_000L)); // < 100 KB
    assertThat(k.relationshipsWithPredicate("communicates-with")).isEmpty();
  }

  @Test
  void internalToInternalIsSkipped() {
    CaseKnowledge k = run(conv("172.16.1.66", "172.16.1.4", 9_000_000L));
    assertThat(k.relationshipsWithPredicate("communicates-with")).isEmpty();
  }
}
