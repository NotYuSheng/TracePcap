package com.tracepcap.cleanup;

import com.tracepcap.file.event.FileDeletedEvent;
import com.tracepcap.file.service.StorageService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Removes the content extracted from a deleted file (#855).
 *
 * <p>Extracted files are real capture content, so leaving them behind means a deletion, or an
 * expiry under {@code FILE_RETENTION_HOURS}, doesn't actually remove the data. The FK cascade can
 * only reach their rows, not the objects in storage.
 *
 * <p>{@code AFTER_COMMIT} so the content is only removed once the delete is durable — a rolled back
 * transaction must not take it with it.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ExtractedContentCleanupListener {

  private final StorageService storageService;

  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
  public void handleFileDeleted(FileDeletedEvent event) {
    try {
      storageService.deleteByPrefix(StorageService.extractedPrefix(event.getFileId()));
    } catch (Exception e) {
      // The file is already gone, so this can't surface as a failed delete to the caller.
      // OrphanedExtractedContentSweeper retries it on its next run.
      log.error("Failed to delete extracted content for deleted file {}", event.getFileId(), e);
    }
  }
}
