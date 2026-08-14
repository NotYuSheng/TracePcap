package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.AnalysisResultEntity;
import com.tracepcap.analysis.repository.AnalysisResultRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

/** Service for async analysis operations */
@Slf4j
@Service
@RequiredArgsConstructor
public class AsyncAnalysisService {

  private final AnalysisService analysisService;
  private final AnalysisRecordService analysisRecordService;
  private final AnalysisResultRepository analysisResultRepository;

  @Async("asyncAnalysisExecutor")
  public void analyzeFileAsync(UUID fileId) {
    log.info("Starting async analysis for file: {}", fileId);
    try {
      analysisService.analyzeFile(fileId);
      log.info("Completed async analysis for file: {}", fileId);
    } catch (Exception e) {
      log.error("Failed async analysis for file {}: {}", fileId, e.getMessage(), e);
      markFailedIfStillPending(fileId, e);
    }
  }

  /**
   * Records a failure that {@code analyzeFile} could not record itself.
   *
   * <p>Its own catch block handles anything thrown inside the method. It cannot handle a failure at
   * commit: a best-effort catch inside the pipeline can leave the transaction rollback-only, and
   * the proxy then throws {@code UnexpectedRollbackException} after {@code analyzeFile} has already
   * returned. This runs outside that transaction, so it is the last place able to say what
   * happened — without it the file sits in PROCESSING until the reconciliation cron notices.
   */
  private void markFailedIfStillPending(UUID fileId, Exception cause) {
    try {
      analysisResultRepository
          .findByFileId(fileId)
          .filter(a -> a.getStatus() != AnalysisResultEntity.AnalysisStatus.FAILED)
          .ifPresent(a -> analysisRecordService.markFailed(a.getId(), fileId, cause.getMessage()));
    } catch (Exception markEx) {
      log.error("Could not mark analysis for file {} as FAILED: {}", fileId, markEx.getMessage());
    }
  }
}
