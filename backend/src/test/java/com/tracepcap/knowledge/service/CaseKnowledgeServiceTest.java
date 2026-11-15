package com.tracepcap.knowledge.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.knowledge.spi.CaseKnowledge;
import com.tracepcap.knowledge.spi.EntityRef;
import com.tracepcap.knowledge.spi.KnowledgeContributor;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class CaseKnowledgeServiceTest {

  private static final UUID FILE = UUID.randomUUID();

  private KnowledgeContributor contributor(String name) {
    return new KnowledgeContributor() {
      @Override public String name() { return name; }
      @Override public void contribute(com.tracepcap.knowledge.spi.KnowledgeContext context, com.tracepcap.knowledge.spi.CaseKnowledgeBuilder board) {
        board.addEntity(EntityRef.host("10.0.0." + name.length()));
      }
    };
  }

  @Test
  void assemblesFromAllContributors() {
    CaseKnowledgeService service =
        service(List.of(contributor("a"), contributor("bb")));

    CaseKnowledge k = service.assemble(FILE);

    assertThat(k.fileId()).isEqualTo(FILE);
    assertThat(k.entities()).hasSize(2); // 10.0.0.1 and 10.0.0.2
  }

  @Test
  void aThrowingContributorIsIsolatedAndTheRestStillAssemble() {
    KnowledgeContributor bad = new KnowledgeContributor() {
      @Override public String name() { return "bad"; }
      @Override public void contribute(com.tracepcap.knowledge.spi.KnowledgeContext context, com.tracepcap.knowledge.spi.CaseKnowledgeBuilder board) {
        throw new IllegalStateException("boom");
      }
    };
    CaseKnowledgeService service = service(List.of(bad, contributor("good")));

    CaseKnowledge k = service.assemble(FILE);

    // the good contributor's entity survives the bad one's failure
    assertThat(k.entities()).hasSize(1);
  }

  @Test
  void noContributors_yieldsAnEmptyBoard() {
    CaseKnowledge k = service(List.of()).assemble(FILE);
    assertThat(k.entities()).isEmpty();
    assertThat(k.relationships()).isEmpty();
    assertThat(k.findings()).isEmpty();
  }

  private final com.tracepcap.analysis.spi.ConversationLookup conversations =
      org.mockito.Mockito.mock(com.tracepcap.analysis.spi.ConversationLookup.class);
  private final com.tracepcap.analysis.spi.HostClassificationLookup hosts =
      org.mockito.Mockito.mock(com.tracepcap.analysis.spi.HostClassificationLookup.class);

  private CaseKnowledgeService service(List<KnowledgeContributor> contributors) {
    return new CaseKnowledgeService(contributors, conversations, hosts);
  }

  /** One assembly loads each fact list once, however many contributors read it (#816). */
  @Test
  void factsAreLoadedOncePerAssembly_notOncePerContributor() {
    org.mockito.Mockito.when(conversations.conversationFacts(FILE)).thenReturn(List.of());
    KnowledgeContributor reader =
        new KnowledgeContributor() {
          @Override public String name() { return "reader"; }
          @Override public void contribute(com.tracepcap.knowledge.spi.KnowledgeContext context, com.tracepcap.knowledge.spi.CaseKnowledgeBuilder board) {
            context.conversationFacts();
            context.conversationFacts();
          }
        };

    service(List.of(reader, reader, reader)).assemble(FILE);

    org.mockito.Mockito.verify(conversations, org.mockito.Mockito.times(1)).conversationFacts(FILE);
    // Nobody asked for hosts, so they are never loaded.
    org.mockito.Mockito.verify(hosts, org.mockito.Mockito.never()).hostFacts(org.mockito.ArgumentMatchers.any());
  }
}
