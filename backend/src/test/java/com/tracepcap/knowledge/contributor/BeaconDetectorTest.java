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
import com.tracepcap.knowledge.spi.EntityType;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class BeaconDetectorTest {

  private static final UUID FILE = UUID.randomUUID();
  private static final TlsFacts NO_TLS = new TlsFacts(null, null, null, null, null, null, null);

  @Mock private ConversationLookup conversationLookup;

  /** host → ext:port over TCP, given packet count / bytes / duration / TLS / initiator. */
  private ConversationFacts flow(
      String host, String ext, int extPort, long pkts, long bytes, long durSec,
      TlsFacts tls, String initiator) {
    LocalDateTime start = LocalDateTime.now();
    return new ConversationFacts(
        UUID.randomUUID(), FILE,
        new FlowIdentity(host, 49754, ext, extPort, initiator, 49754, "TCP", pkts, bytes,
            start, start.plusSeconds(durSec)),
        tls,
        new Findings(null, null, null, List.of(), List.of(), List.of(), List.of()));
  }

  private CaseKnowledge run(ConversationFacts... convs) {
    when(conversationLookup.conversationFacts(FILE)).thenReturn(List.of(convs));
    CaseKnowledgeBuilder board = new CaseKnowledgeBuilder(FILE);
    new BeaconDetector(conversationLookup).contribute(FILE, board);
    return board.build();
  }

  @Test
  void flagsSustainedRawTcpBeaconOnAnOddPort() {
    // STRRAT: 206 pkts, ~194 B/pkt, minutes long, port 12132, no TLS, host-initiated.
    CaseKnowledge k = run(flow("172.16.1.66", "141.98.10.79", 12132, 206, 40_000, 300, NO_TLS, "172.16.1.66"));

    assertThat(k.findingsOfCategory("suspected-beacon")).singleElement().satisfies(f -> {
      assertThat(f.concerns()).contains(EntityRef.host("172.16.1.66"), EntityRef.external("141.98.10.79"));
      assertThat(f.evidence()).hasSize(1);
      assertThat(f.attributes()).containsEntry("dstPort", 12132);
    });
    assertThat(k.entitiesOfType(EntityType.EXTERNAL_SERVICE)).singleElement()
        .satisfies(e -> assertThat(e.key()).isEqualTo("141.98.10.79"));
    assertThat(k.relationshipsWithPredicate("communicates-with")).singleElement()
        .satisfies(r -> assertThat(r.from()).isEqualTo(EntityRef.host("172.16.1.66")));
  }

  @Test
  void ignoresTlsSessions() {
    // Same shape, but it's TLS (has a JA3) → ordinary HTTPS on an odd port, not a raw beacon.
    TlsFacts tls = new TlsFacts("cdn.example.com", null, null, null, null, "ja3abc", null);
    CaseKnowledge k = run(flow("172.16.1.66", "23.1.2.3", 44300, 206, 40_000, 300, tls, "172.16.1.66"));
    assertThat(k.findings()).isEmpty();
  }

  @Test
  void ignoresStandardServicePorts() {
    CaseKnowledge k = run(flow("172.16.1.66", "23.1.2.3", 443, 206, 40_000, 300, NO_TLS, "172.16.1.66"));
    assertThat(k.findings()).isEmpty();
  }

  @Test
  void ignoresBulkTransfersAndShortConnections() {
    // High throughput (bulk) — that's the data-transfer path, not a beacon.
    assertThat(run(flow("172.16.1.66", "141.98.10.79", 12132, 206, 40_000_000L, 300, NO_TLS, "172.16.1.66"))
        .findings()).isEmpty();
    // Too few packets to be a sustained channel.
    assertThat(run(flow("172.16.1.66", "141.98.10.79", 12132, 5, 900, 300, NO_TLS, "172.16.1.66"))
        .findings()).isEmpty();
  }

  @Test
  void ignoresInternalToInternalAndInboundFlows() {
    // both endpoints internal → no external C2 to suspect
    assertThat(run(flow("172.16.1.66", "172.16.1.4", 12132, 206, 40_000, 300, NO_TLS, "172.16.1.66"))
        .findings()).isEmpty();
    // the external opened the connection (inbound) → not an outbound beacon
    assertThat(run(flow("172.16.1.66", "141.98.10.79", 12132, 206, 40_000, 300, NO_TLS, "141.98.10.79"))
        .findings()).isEmpty();
  }
}
