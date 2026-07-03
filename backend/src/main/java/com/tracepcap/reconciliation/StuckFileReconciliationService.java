package com.tracepcap.reconciliation;

import com.tracepcap.analysis.service.AnalysisRecordService;
import com.tracepcap.config.ReconciliationProperties;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.entity.FileEntity.FileStatus;
import com.tracepcap.file.repository.FileRepository;
import java.time.LocalDateTime;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Recovers files that are stuck in {@link FileStatus#PROCESSING} — analysis that was never
 * submitted (rejected during shutdown), or a worker lost to a crash/restart (the async queue is
 * in-memory and does not survive a restart). Any such file whose upload predates a configurable
 * timeout is flipped to FAILED so it surfaces in the UI and can be retried instead of showing
 * "processing" forever (see #451).
 */
@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnProperty(
    prefix = "tracepcap.reconciliation",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true)
public class StuckFileReconciliationService {

  private final FileRepository fileRepository;
  private final AnalysisRecordService analysisRecordService;
  private final ReconciliationProperties properties;

  /** Scheduled task that flips files stuck in PROCESSING past the timeout to FAILED. */
  @Scheduled(cron = "${tracepcap.reconciliation.cron}")
  public void reconcileStuckFiles() {
    if (!properties.isEnabled()) {
      log.debug("Stuck-file reconciliation is disabled");
      return;
    }

    LocalDateTime cutoff = LocalDateTime.now().minusMinutes(properties.getTimeoutMinutes());
    List<FileEntity> stuck =
        fileRepository.findByStatusAndUploadedAtBefore(FileStatus.PROCESSING, cutoff);

    if (stuck.isEmpty()) {
      log.debug("No stuck files found (cutoff: {})", cutoff);
      return;
    }

    log.warn("Found {} file(s) stuck in PROCESSING before {}; marking FAILED", stuck.size(), cutoff);

    String message =
        "Analysis did not complete within "
            + properties.getTimeoutMinutes()
            + " minutes (queue overflow, worker crash, or restart). Re-upload to retry.";

    int recovered = 0;
    for (FileEntity file : stuck) {
      try {
        analysisRecordService.markStuckFileFailed(file.getId(), message);
        recovered++;
      } catch (Exception e) {
        log.error(
            "Failed to reconcile stuck file {} (ID: {}): {}",
            file.getFileName(),
            file.getId(),
            e.getMessage());
      }
    }

    log.warn("Stuck-file reconciliation completed. Recovered {}/{}", recovered, stuck.size());
  }
}
