package com.tracepcap.cleanup;

import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.file.service.StorageService;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Removes extracted content whose file no longer exists (#855).
 *
 * <p>{@link ExtractedContentCleanupListener} handles the normal case. This catches what it can't:
 * content left by versions before that listener existed, a delete that happened while storage was
 * unavailable, and an extraction that finished writing just after its file was deleted.
 *
 * <p>Deliberately not gated on {@code tracepcap.cleanup.enabled}, unlike {@link
 * FileCleanupService}. That switch keeps files; this only touches content whose file is already
 * gone.
 *
 * <p>Folders are listed before their files are looked up. A file's row is committed before anything
 * is extracted from it, so a folder that exists always had a row by then, and a missing row means
 * the file was deleted rather than not yet saved.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class OrphanedExtractedContentSweeper {

  private final StorageService storageService;
  private final FileRepository fileRepository;

  @Scheduled(cron = "${tracepcap.cleanup.cron}")
  public void sweep() {
    int swept = 0;
    int failed = 0;

    try {
      for (String folder : storageService.listFolders(StorageService.EXTRACTED_ROOT)) {
        UUID fileId = parseFileId(folder);
        if (fileId == null || fileRepository.existsById(fileId)) {
          continue;
        }
        try {
          storageService.deleteByPrefix(StorageService.extractedPrefix(fileId));
          swept++;
        } catch (Exception e) {
          // One bad folder must not stop the rest; it is retried on the next run.
          log.error("Failed to sweep extracted content for missing file {}", fileId, e);
          failed++;
        }
      }
    } catch (Exception e) {
      log.error("Error while sweeping orphaned extracted content", e);
      return;
    }

    if (swept > 0 || failed > 0) {
      log.info("Orphaned extracted content sweep: removed {}, failed {}", swept, failed);
    }
  }

  /** Anything that isn't a file id wasn't written by extraction, so it is left alone. */
  private UUID parseFileId(String folder) {
    try {
      return UUID.fromString(folder);
    } catch (IllegalArgumentException e) {
      log.warn("Skipping unexpected folder under {}: {}", StorageService.EXTRACTED_ROOT, folder);
      return null;
    }
  }
}
