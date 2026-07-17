package com.tracepcap.analysis.service;

import com.tracepcap.analysis.repository.AnalysisResultRepository;
import com.tracepcap.analysis.spi.AnalysisSummaryLookup;
import java.util.Collections;
import java.util.LinkedHashMap;
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
   * Wraps the deserialised jsonb map so a consumer cannot edit the fact base through the returned
   * reference.
   *
   * <p>{@code unmodifiableMap} rather than {@code Map.copyOf}: jsonb permits null values, and {@code
   * Map.copyOf} throws on them. Nothing writes a null today, but this is a schema-free column — the
   * guarantee the port owes callers is immutability, and it should not become an NPE the first time
   * the pipeline emits a null stat.
   */
  private static Map<String, Object> unmodifiable(Map<String, Object> stats) {
    return stats == null ? Map.of() : Collections.unmodifiableMap(new LinkedHashMap<>(stats));
  }
}
