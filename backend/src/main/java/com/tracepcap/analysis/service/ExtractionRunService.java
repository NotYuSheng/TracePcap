package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.ExtractionRunEntity;
import com.tracepcap.analysis.repository.ExtractionRunRepository;
import com.tracepcap.analysis.spi.ExtractionManifest;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Records and serves the extraction run manifest (#512 slice 2). The pipeline calls
 * {@link #record}; downstream consumers read through the {@link ExtractionManifest} port.
 *
 * <p>Recording is best-effort and never fails the analysis — a manifest write failure logs a
 * warning and the pipeline continues. REQUIRES_NEW keeps each row visible even if a later stage
 * rolls back, and isolates the manifest from the pipeline's own transaction boundaries.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class ExtractionRunService implements ExtractionManifest {

  /** Bump when an extractor's output semantics change enough to warrant re-extraction. */
  static final String VERSION = "1";

  private final ExtractionRunRepository repository;

  @Override
  public Optional<Run> runFor(UUID fileId, String extractor) {
    return repository
        .findByFileIdAndExtractor(fileId, extractor)
        .map(
            e ->
                new Run(
                    e.getExtractor(),
                    e.getVersion(),
                    Status.valueOf(e.getStatus()),
                    e.getDetail()));
  }

  /**
   * Replaces this file+extractor's row (re-analysis overwrites the previous run's record).
   * Updates in place rather than delete-then-insert: with IDENTITY ids Hibernate flushes the
   * INSERT immediately while the DELETE stays queued, which would trip the unique constraint on
   * every re-analysis.
   */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void record(UUID fileId, String extractor, Status status, String detail) {
    try {
      ExtractionRunEntity entity =
          repository
              .findByFileIdAndExtractor(fileId, extractor)
              .orElseGet(
                  () -> ExtractionRunEntity.builder().fileId(fileId).extractor(extractor).build());
      entity.setVersion(VERSION);
      entity.setStatus(status.name());
      entity.setDetail(detail);
      repository.save(entity);
    } catch (Exception e) {
      log.warn(
          "Failed to record extraction run {}={} for file {}: {}",
          extractor,
          status,
          fileId,
          e.getMessage());
    }
  }
}
