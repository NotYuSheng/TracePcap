package com.lanturn.cleanup;

import com.lanturn.config.CleanupProperties;
import com.lanturn.file.entity.FileEntity;
import com.lanturn.file.entity.FileEntity.FileSource;
import com.lanturn.file.repository.FileRepository;
import com.lanturn.file.service.FileService;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/** Service to handle scheduled cleanup of expired files */
@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnProperty(
    prefix = "lanturn.cleanup",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true)
public class FileCleanupService {

  private final FileRepository fileRepository;
  private final FileService fileService;
  private final CleanupProperties cleanupProperties;

  /**
   * Scheduled task to clean up expired files Runs according to the cron expression configured in
   * application.yml
   */
  @Scheduled(cron = "${lanturn.cleanup.cron}")
  public void cleanupExpiredFiles() {
    if (!cleanupProperties.isEnabled()) {
      log.debug("File cleanup is disabled");
      return;
    }

    log.info("Starting scheduled file cleanup task");

    try {
      List<FileEntity> expiredFiles = new ArrayList<>();

      // Analysis files — always apply retention
      LocalDateTime analysisExpiry =
          LocalDateTime.now().minusHours(cleanupProperties.getRetentionHours());
      log.info("Checking analysis files uploaded before: {}", analysisExpiry);
      expiredFiles.addAll(
          fileRepository.findBySourceAndUploadedAtBefore(FileSource.ANALYSIS, analysisExpiry));

      // Monitor files — only apply if monitorRetentionHours > 0
      if (cleanupProperties.getMonitorRetentionHours() > 0) {
        LocalDateTime monitorExpiry =
            LocalDateTime.now().minusHours(cleanupProperties.getMonitorRetentionHours());
        log.info("Checking monitor files uploaded before: {}", monitorExpiry);
        expiredFiles.addAll(
            fileRepository.findBySourceAndUploadedAtBefore(FileSource.MONITOR, monitorExpiry));
      }

      if (expiredFiles.isEmpty()) {
        log.info("No expired files found");
        return;
      }

      log.info("Found {} expired files to delete", expiredFiles.size());

      // Delete each expired file
      int successCount = 0;
      int failureCount = 0;

      for (FileEntity file : expiredFiles) {
        try {
          log.info(
              "Deleting expired file: {} (ID: {}, uploaded at: {})",
              file.getFileName(),
              file.getId(),
              file.getUploadedAt());

          fileService.deleteFile(file.getId());
          successCount++;

        } catch (Exception e) {
          log.error(
              "Failed to delete expired file: {} (ID: {})", file.getFileName(), file.getId(), e);
          failureCount++;
        }
      }

      log.info(
          "File cleanup completed. Successfully deleted: {}, Failed: {}",
          successCount,
          failureCount);

    } catch (Exception e) {
      log.error("Error during scheduled file cleanup", e);
    }
  }
}
