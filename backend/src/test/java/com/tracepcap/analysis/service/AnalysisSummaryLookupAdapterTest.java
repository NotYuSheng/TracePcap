package com.tracepcap.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.tracepcap.analysis.entity.AnalysisResultEntity;
import com.tracepcap.analysis.repository.AnalysisResultRepository;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * {@code CaptureSummary.protocolStats} promises immutability, and {@code protocol_stats} nests —
 * {@code {"ARP": {"bytes": 7476}}} — so the promise has to hold more than one level down (#512
 * slice 6d review). A shallow wrap leaves the inner maps aliasing the entity's own graph.
 */
class AnalysisSummaryLookupAdapterTest {

  private static final UUID FILE = UUID.randomUUID();

  private final AnalysisResultRepository repository = mock(AnalysisResultRepository.class);
  private final AnalysisSummaryLookupAdapter adapter = new AnalysisSummaryLookupAdapter(repository);

  private static AnalysisResultEntity withStats(Map<String, Object> stats) {
    return AnalysisResultEntity.builder()
        .packetCount(10L)
        .totalBytes(100L)
        .protocolStats(stats)
        .build();
  }

  @Test
  void nestedProtocolStatsAreImmutableToo() {
    Map<String, Object> inner = new HashMap<>();
    inner.put("bytes", 7476);
    inner.put("packetCount", 178);
    Map<String, Object> stats = new LinkedHashMap<>();
    stats.put("ARP", inner);
    when(repository.findByFileId(FILE)).thenReturn(Optional.of(withStats(stats)));

    Map<String, Object> served = adapter.summaryFor(FILE).orElseThrow().protocolStats();

    assertThat(served).containsOnlyKeys("ARP");
    // The outer map is the easy half.
    assertThatThrownBy(() -> served.put("TCP", Map.of()))
        .isInstanceOf(UnsupportedOperationException.class);
    // The half a shallow wrap misses: this is what would rewrite the fact base.
    @SuppressWarnings("unchecked")
    Map<String, Object> servedInner = (Map<String, Object>) served.get("ARP");
    assertThatThrownBy(() -> servedInner.put("bytes", 0))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  void mutatingTheSourceAfterwardsDoesNotChangeWhatWasServed() {
    Map<String, Object> inner = new HashMap<>();
    inner.put("bytes", 7476);
    Map<String, Object> stats = new LinkedHashMap<>();
    stats.put("ARP", inner);
    when(repository.findByFileId(FILE)).thenReturn(Optional.of(withStats(stats)));

    Map<String, Object> served = adapter.summaryFor(FILE).orElseThrow().protocolStats();
    inner.put("bytes", 999999); // the entity's graph moves on

    @SuppressWarnings("unchecked")
    Map<String, Object> servedInner = (Map<String, Object>) served.get("ARP");
    assertThat(servedInner).containsEntry("bytes", 7476);
  }

  /** jsonb permits nulls; Map.copyOf would throw on them, so the copy must tolerate them. */
  @Test
  void nullStatValuesSurviveTheCopy() {
    Map<String, Object> stats = new LinkedHashMap<>();
    stats.put("ODD", null);
    when(repository.findByFileId(FILE)).thenReturn(Optional.of(withStats(stats)));

    assertThat(adapter.summaryFor(FILE).orElseThrow().protocolStats()).containsEntry("ODD", null);
  }

  @Test
  void absentStatsBecomeAnEmptyMapNotNull() {
    when(repository.findByFileId(FILE)).thenReturn(Optional.of(withStats(null)));
    assertThat(adapter.summaryFor(FILE).orElseThrow().protocolStats()).isEmpty();
  }

  @Test
  void unanalysedFileIsEmptyOptional() {
    when(repository.findByFileId(FILE)).thenReturn(Optional.empty());
    assertThat(adapter.summaryFor(FILE)).isEmpty();
  }
}
