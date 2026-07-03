package com.tracepcap.analysis.service;

import com.tracepcap.analysis.entity.AnalysisResultEntity;
import com.tracepcap.analysis.repository.AnalysisResultRepository;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Manages analysis result record lifecycle in independent transactions so that status changes
 * (IN_PROGRESS, FAILED) are immediately visible to other transactions — even while the main
 * analysis transaction is still open.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AnalysisRecordService {

  private final AnalysisResultRepository analysisResultRepository;
  private final FileRepository fileRepository;

  /**
   * Creates and immediately commits an IN_PROGRESS analysis record. Uses REQUIRES_NEW so the insert
   * is visible to polling queries before the long-running analysis transaction completes.
   */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public AnalysisResultEntity createInProgress(FileEntity file) {
    AnalysisResultEntity analysis =
        AnalysisResultEntity.builder()
            .file(file)
            .status(AnalysisResultEntity.AnalysisStatus.IN_PROGRESS)
            .build();
    return analysisResultRepository.save(analysis);
  }

  /**
   * Marks both the analysis record and its parent file as FAILED and immediately commits. Uses
   * REQUIRES_NEW so the update persists even when called from a catch block where the outer
   * transaction is being rolled back.
   */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void markFailed(UUID analysisId, UUID fileId, String errorMessage) {
    analysisResultRepository
        .findById(analysisId)
        .ifPresent(
            analysis -> {
              analysis.setStatus(AnalysisResultEntity.AnalysisStatus.FAILED);
              analysis.setErrorMessage(errorMessage != null ? errorMessage : "Unknown error");
              analysisResultRepository.save(analysis);
              log.info("Marked analysis {} as FAILED", analysisId);
            });
    markFileFailed(fileId);
  }

  /**
   * Reconciles a file that is stuck in PROCESSING (analysis never ran, or the worker was lost on a
   * crash/restart): flips the file to FAILED and ensures a FAILED analysis record exists so the
   * failure surfaces in the UI. Runs in its own committed transaction.
   */
  @Transactional(propagation = Propagation.REQUIRES_NEW)
  public void markStuckFileFailed(UUID fileId, String errorMessage) {
    String message = errorMessage != null ? errorMessage : "Analysis did not complete";
    analysisResultRepository
        .findByFileId(fileId)
        .ifPresentOrElse(
            analysis -> {
              // Leave already-completed analyses untouched; only recover in-flight/pending ones.
              if (analysis.getStatus() != AnalysisResultEntity.AnalysisStatus.COMPLETED) {
                analysis.setStatus(AnalysisResultEntity.AnalysisStatus.FAILED);
                analysis.setErrorMessage(message);
                analysisResultRepository.save(analysis);
              }
            },
            () ->
                fileRepository
                    .findById(fileId)
                    .ifPresent(
                        file ->
                            analysisResultRepository.save(
                                AnalysisResultEntity.builder()
                                    .file(file)
                                    .status(AnalysisResultEntity.AnalysisStatus.FAILED)
                                    .errorMessage(message)
                                    .build())));
    markFileFailed(fileId);
  }

  private void markFileFailed(UUID fileId) {
    fileRepository
        .findById(fileId)
        .ifPresent(
            file -> {
              file.setStatus(FileEntity.FileStatus.FAILED);
              fileRepository.save(file);
            });
  }
}
