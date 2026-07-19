package com.tracepcap.analysis.service;

import com.tracepcap.analysis.dto.AnalysisProgressResponse;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Service;

/**
 * In-memory, per-file live analysis progress. The analysis pipeline runs inside one long
 * transaction, so nothing it writes is visible to pollers until it commits at the very end — this
 * bean is the out-of-band channel that publishes progress <em>during</em> the run.
 *
 * <p>Intentionally not persisted: progress is ephemeral and only meaningful while the (single)
 * backend is running the job. Entries are cleared when the job finishes or fails, so the map stays
 * bounded by the number of concurrently-analysing files. A process restart simply drops progress
 * and the loading view falls back to its size-based estimate.
 */
@Service
public class AnalysisProgressService {

  private final ConcurrentHashMap<UUID, AnalysisProgressResponse> progressByFile =
      new ConcurrentHashMap<>();

  /** Publishes the latest progress for a file, overwriting any previous value. */
  public void update(UUID fileId, AnalysisProgressResponse progress) {
    progressByFile.put(fileId, progress);
  }

  /** Current progress for a file, or empty if none is being tracked. */
  public Optional<AnalysisProgressResponse> get(UUID fileId) {
    return Optional.ofNullable(progressByFile.get(fileId));
  }

  /** Drops tracking for a file once its analysis has finished (success or failure). */
  public void clear(UUID fileId) {
    progressByFile.remove(fileId);
  }
}
