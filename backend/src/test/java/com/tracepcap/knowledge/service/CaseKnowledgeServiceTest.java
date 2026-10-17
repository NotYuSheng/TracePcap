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
      @Override public void contribute(UUID fileId, com.tracepcap.knowledge.spi.CaseKnowledgeBuilder board) {
        board.addEntity(EntityRef.host("10.0.0." + name.length()));
      }
    };
  }

  @Test
  void assemblesFromAllContributors() {
    CaseKnowledgeService service =
        new CaseKnowledgeService(List.of(contributor("a"), contributor("bb")));

    CaseKnowledge k = service.assemble(FILE);

    assertThat(k.fileId()).isEqualTo(FILE);
    assertThat(k.entities()).hasSize(2); // 10.0.0.1 and 10.0.0.2
  }

  @Test
  void aThrowingContributorIsIsolatedAndTheRestStillAssemble() {
    KnowledgeContributor bad = new KnowledgeContributor() {
      @Override public String name() { return "bad"; }
      @Override public void contribute(UUID fileId, com.tracepcap.knowledge.spi.CaseKnowledgeBuilder board) {
        throw new IllegalStateException("boom");
      }
    };
    CaseKnowledgeService service = new CaseKnowledgeService(List.of(bad, contributor("good")));

    CaseKnowledge k = service.assemble(FILE);

    // the good contributor's entity survives the bad one's failure
    assertThat(k.entities()).hasSize(1);
  }

  @Test
  void noContributors_yieldsAnEmptyBoard() {
    CaseKnowledge k = new CaseKnowledgeService(List.of()).assemble(FILE);
    assertThat(k.entities()).isEmpty();
    assertThat(k.relationships()).isEmpty();
    assertThat(k.findings()).isEmpty();
  }
}
