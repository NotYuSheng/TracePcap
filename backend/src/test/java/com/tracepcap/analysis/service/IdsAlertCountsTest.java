package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.entity.IdsAlertCountEntity;
import com.tracepcap.analysis.entity.IdsAlertEntity;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/** Each conversation's alert count is saved beside how many records it kept (#1284). */
class IdsAlertCountsTest {

  @Test
  void savesTotalAndKept_perConversationThatHadAlerts() {
    UUID file = UUID.randomUUID();
    PcapParserService.ConversationInfo noisy = conv(UUID.randomUUID(), 450);
    PcapParserService.ConversationInfo quiet = conv(UUID.randomUUID(), 0);
    PcapParserService.ConversationInfo unsaved = conv(null, 3);
    List<IdsAlertEntity> rows = List.of(row(file, noisy), row(file, noisy));

    List<IdsAlertCountEntity> out = AnalysisService.alertCounts(file, List.of(noisy, quiet, unsaved), rows);

    assertThat(out).singleElement().satisfies(c -> {
      assertThat(c.getConversationId()).isEqualTo(noisy.getEntityId());
      assertThat(c.getTotal()).isEqualTo(450);
      assertThat(c.getKept()).isEqualTo(2);
      assertThat(c.getSrcIp()).isEqualTo("10.0.0.5");
    });
  }

  @Test
  void theTotalIsNeverBelowWhatWasKept() {
    UUID file = UUID.randomUUID();
    PcapParserService.ConversationInfo c = conv(UUID.randomUUID(), 0);
    assertThat(AnalysisService.alertCounts(file, List.of(c), List.of(row(file, c))))
        .singleElement().satisfies(x -> assertThat(x.getTotal()).isEqualTo(1));
  }

  @Test
  void aSharedFlow_isCountedUnderTheFirstSavedConversation_once() {
    // The first on the flow wasn't saved: its count goes to the next, where its records went.
    UUID file = UUID.randomUUID();
    PcapParserService.ConversationInfo unsaved = conv(null, 4512), a = conv(UUID.randomUUID(), 4512),
        b = conv(UUID.randomUUID(), 4512);
    for (var c : List.of(unsaved, a, b)) c.setIdsAlertFlow("flow-1");
    List<IdsAlertEntity> rows = List.of(row(file, a), row(file, a));

    assertThat(AnalysisService.alertCounts(file, List.of(unsaved, a, b), rows)).singleElement()
        .satisfies(c -> {
          assertThat(c.getConversationId()).isEqualTo(a.getEntityId());
          assertThat(c.getTotal()).isEqualTo(4512);
          assertThat(c.getKept()).isEqualTo(2);
        });
  }

  private static PcapParserService.ConversationInfo conv(UUID id, int total) {
    PcapParserService.ConversationInfo c = new PcapParserService.ConversationInfo();
    c.setEntityId(id);
    c.setSrcIp("10.0.0.5");
    c.setDstIp("203.0.113.9");
    c.setIdsAlertTotal(total);
    return c;
  }

  private static IdsAlertEntity row(UUID file, PcapParserService.ConversationInfo c) {
    return IdsAlertEntity.builder().fileId(file).conversationId(c.getEntityId()).sid(1L).signature("x").build();
  }
}
