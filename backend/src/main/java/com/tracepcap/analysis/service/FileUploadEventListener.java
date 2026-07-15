package com.tracepcap.analysis.service;

import com.tracepcap.file.event.FileUploadedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Bridges Ingest to Extract: reacts to the {@code file} module's upload event by scheduling
 * analysis. Lives in {@code analysis} — the publisher owns the event, the consumer owns the
 * listener — so {@code file} needs no knowledge of {@code analysis} (#512, breaks the
 * {@code analysis ↔ file} cycle).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class FileUploadEventListener {

  private final AsyncAnalysisService asyncAnalysisService;

  /** Triggered AFTER the upload transaction commits successfully */
  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
  public void handleFileUploaded(FileUploadedEvent event) {
    log.info(
        "File upload transaction committed, triggering async analysis for file: {}",
        event.getFileId());
    asyncAnalysisService.analyzeFileAsync(event.getFileId());
    log.info("Async analysis task submitted for file: {}", event.getFileId());
  }
}
