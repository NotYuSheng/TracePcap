package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.entity.ConversationEntity;
import com.tracepcap.analysis.repository.ConversationRepository;
import com.tracepcap.analysis.spi.ConversationLookup.ConversationFacts;
import com.tracepcap.file.entity.FileEntity;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * The adapter owns the contracts {@code ConversationLookup}'s javadoc advertises (#512 slice 6c):
 * immutable finding lists, grouped fact grades, and a fileId that doesn't need a lazy-load to reach.
 */
class ConversationLookupAdapterTest {

  private static final UUID FILE = UUID.randomUUID();

  private final ConversationRepository repository = mock(ConversationRepository.class);
  private final ConversationLookupAdapter adapter = new ConversationLookupAdapter(repository);

  private static ConversationEntity conv(String srcIp, String[] risks) {
    return ConversationEntity.builder()
        .id(UUID.randomUUID())
        .file(FileEntity.builder().id(FILE).build())
        .srcIp(srcIp)
        .srcPort(51000)
        .dstIp("10.0.0.2")
        .dstPort(443)
        .protocol("TCP")
        .packetCount(10L)
        .totalBytes(1500L)
        .appName("TLS")
        .flowRisks(risks)
        .build();
  }

  /**
   * The columns are Postgres arrays. Handing back a view onto the entity's own array would let any
   * consumer write through it and corrupt the fact base — so the port promises immutability.
   */
  @Test
  void findingListsAreImmutable() {
    when(repository.findByFileId(FILE))
        .thenReturn(List.of(conv("10.0.0.1", new String[] {"MALWARE", "SCAN"})));

    List<String> risks = adapter.conversationFacts(FILE).get(0).findings().flowRisks();

    assertThat(risks).containsExactly("MALWARE", "SCAN");
    assertThatThrownBy(() -> risks.add("INJECTED"))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void absentArraysBecomeEmptyListsNotNull() {
    when(repository.findByFileId(FILE))
        .thenReturn(List.of(conv("10.0.0.1", null), conv("10.0.0.2", new String[] {})));

    assertThat(adapter.conversationFacts(FILE))
        .allSatisfy(
            f -> {
              assertThat(f.findings().flowRisks()).isEmpty();
              assertThat(f.findings().suricataAlerts()).isEmpty();
              assertThat(f.findings().customSignatures()).isEmpty();
              assertThat(f.findings().httpUserAgents()).isEmpty();
            });
  }

  /** Grades are the point of the grouping: a measurement and an inference must not sit side by side. */
  @Test
  void factsAreGroupedByGrade() {
    when(repository.findByFileId(FILE)).thenReturn(List.of(conv("10.0.0.1", new String[] {"SCAN"})));

    ConversationFacts f = adapter.conversationFacts(FILE).get(0);

    assertThat(f.flow().srcIp()).isEqualTo("10.0.0.1"); // MEASURED
    assertThat(f.flow().packetCount()).isEqualTo(10L);
    assertThat(f.findings().appName()).isEqualTo("TLS"); // INFERRED — nDPI's guess, not a measurement
    assertThat(f.findings().flowRisks()).containsExactly("SCAN");
    assertThat(f.tls()).isNotNull(); // never a null group, even with no TLS on the wire
    assertThat(f.tls().tlsSubject()).isNull();
    assertThat(f.fileId()).isEqualTo(FILE);
  }

  @Test
  void emptyOrNullIdSetShortCircuitsWithoutQuerying() {
    assertThat(adapter.conversationFactsByIds(Set.of())).isEmpty();
    assertThat(adapter.conversationFactsByIds(null)).isEmpty();
    verify(repository, never()).findAllById(anyCollection());
  }

  @Test
  void missingConversationIsEmptyOptional() {
    UUID id = UUID.randomUUID();
    when(repository.findById(id)).thenReturn(java.util.Optional.empty());
    assertThat(adapter.conversationFactsById(id)).isEmpty();
  }
}
