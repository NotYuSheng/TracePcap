package com.tracepcap.story.service;

import static org.assertj.core.api.Assertions.assertThat;

import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.analysis.spi.ConversationLookup.FlowIdentity;
import com.tracepcap.story.dto.StoryAggregates;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class StoryConnectionOutcomesTest {

  private static final LocalDateTime T = LocalDateTime.of(2026, 11, 22, 10, 0);

  /** Stored src/dst are sorted, not directional: the initiator says who tried. */
  private static ConversationFacts conv(
      String a, int aPort, String b, int bPort, String initiator, String outcome) {
    return new ConversationFacts(
        UUID.randomUUID(), UUID.randomUUID(),
        new FlowIdentity(a, aPort, b, bPort, initiator, initiator == null ? null : (initiator.equals(a) ? aPort : bPort),
            "TCP", 2, 120, T, T, null, null, outcome),
        null, null);
  }

  @Test
  void countsEachOutcome_andRanksTheFailedTargets_fromTheInitiatorsSide() {
    List<ConversationFacts> all = new ArrayList<>();
    all.add(conv("10.0.0.5", 50001, "203.0.113.9", 443, "10.0.0.5", "ANSWERED"));
    // A sweep of port 22 on one target: three unanswered, one refused. The scanner sorts second.
    for (int p = 50010; p < 50013; p++) all.add(conv("10.0.0.20", 22, "10.0.0.99", p, "10.0.0.99", "NO_ANSWER"));
    all.add(conv("10.0.0.20", 22, "10.0.0.99", 50020, "10.0.0.99", "REJECTED"));
    all.add(conv("10.0.0.5", 50030, "198.51.100.7", 8080, "10.0.0.5", "NO_ANSWER"));
    all.add(conv("10.0.0.5", 5353, "224.0.0.251", 5353, null, null)); // not TCP: ignored

    StoryAggregates.ConnectionOutcomes o = StoryAggregatesService.computeConnectionOutcomes(all);

    assertThat(o.getAnswered()).isEqualTo(1);
    assertThat(o.getNoAnswer()).isEqualTo(4);
    assertThat(o.getRejected()).isEqualTo(1);
    assertThat(o.getTopFailedTargets()).hasSize(2);
    StoryAggregates.FailedTarget top = o.getTopFailedTargets().get(0);
    assertThat(top.getSrcIp()).isEqualTo("10.0.0.99");
    assertThat(top.getDstIp()).isEqualTo("10.0.0.20");
    assertThat(top.getDstPort()).isEqualTo(22);
    assertThat(top.getNoAnswer()).isEqualTo(3);
    assertThat(top.getRejected()).isEqualTo(1);
  }

  @Test
  void captureWithoutTcpOutcomes_isAllZero() {
    StoryAggregates.ConnectionOutcomes o = StoryAggregatesService.computeConnectionOutcomes(List.of());
    assertThat(o.getAnswered() + o.getNoAnswer() + o.getRejected()).isZero();
    assertThat(o.getTopFailedTargets()).isEmpty();
  }
}
