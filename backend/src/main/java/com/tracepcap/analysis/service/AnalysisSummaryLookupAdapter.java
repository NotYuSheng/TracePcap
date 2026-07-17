package com.tracepcap.analysis.service;

import com.tracepcap.analysis.repository.AnalysisResultRepository;
import com.tracepcap.analysis.spi.AnalysisSummaryLookup;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/** Serves {@link AnalysisSummaryLookup} from the analysis module's own repository. */
@Component
@RequiredArgsConstructor
public class AnalysisSummaryLookupAdapter implements AnalysisSummaryLookup {

  private final AnalysisResultRepository repository;

  @Override
  public Optional<CaptureSummary> summaryFor(UUID fileId) {
    return repository
        .findByFileId(fileId)
        .map(
            e ->
                new CaptureSummary(
                    e.getPacketCount() == null ? 0L : e.getPacketCount(),
                    e.getTotalBytes() == null ? 0L : e.getTotalBytes(),
                    e.getStartTime(),
                    e.getEndTime(),
                    e.getDurationMs(),
                    unmodifiable(e.getProtocolStats())));
  }

  /**
   * Deep-copies the deserialised jsonb graph so a consumer cannot edit the fact base through the
   * returned reference.
   *
   * <p><b>Deep, not shallow.</b> {@code protocol_stats} nests — {@code {"ARP": {"bytes": 7476,
   * "packetCount": 178}}} — so wrapping only the outer map leaves {@code stats.get("ARP")} aliasing
   * the entity's own map, and {@code .put("bytes", 0)} on it would rewrite the fact base. The port
   * promises immutability, and a promise that only holds one level down is not one.
   *
   * <p>{@code unmodifiableMap} rather than {@code Map.copyOf}: jsonb permits null values and {@code
   * Map.copyOf} throws on them. Nothing writes a null today, but this is a schema-free column, and
   * the guarantee owed here is immutability — not an NPE the first time the pipeline emits a null
   * stat.
   */
  private static Map<String, Object> unmodifiable(Map<String, Object> stats) {
    if (stats == null) return Map.of();
    Map<String, Object> copy = new LinkedHashMap<>();
    stats.forEach((key, value) -> copy.put(key, deepCopy(value)));
    return Collections.unmodifiableMap(copy);
  }

  /** Recursively copies a jsonb value. Scalars are immutable already and pass through. */
  @SuppressWarnings("unchecked")
  private static Object deepCopy(Object value) {
    if (value instanceof Map<?, ?> map) {
      return unmodifiable((Map<String, Object>) map);
    }
    if (value instanceof List<?> list) {
      List<Object> copy = new ArrayList<>(list.size());
      list.forEach(item -> copy.add(deepCopy(item)));
      return Collections.unmodifiableList(copy);
    }
    return value;
  }
}
