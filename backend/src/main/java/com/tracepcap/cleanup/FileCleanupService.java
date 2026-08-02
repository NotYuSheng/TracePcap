package com.tracepcap.cleanup;

import com.tracepcap.analysis.spi.PacketPartitions;
import com.tracepcap.config.CleanupProperties;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.entity.FileEntity.FileSource;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.file.service.FileService;
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
    prefix = "tracepcap.cleanup",
    name = "enabled",
    havingValue = "true",
    matchIfMissing = true)
public class FileCleanupService {

  private final FileRepository fileRepository;
  private final FileService fileService;
  private final CleanupProperties cleanupProperties;
  private final PacketPartitions packetPartitions;

  /**
   * Scheduled task to clean up expired files Runs according to the cron expression configured in
   * application.yml
   */
  @Scheduled(cron = "${tracepcap.cleanup.cron}")
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

  /**
   * Prunes raw packets from files that have outlived {@code packetRetentionHours} but not their own
   * retention window (#394).
   *
   * <p>Runs on the same schedule as file cleanup but as a separate task, so a failure to prune
   * packets never stops expired files from being deleted (or vice versa). Dropping the partition is
   * an O(1) unlink, so this stays cheap no matter how many frames the file held.
   */
  @Scheduled(cron = "${tracepcap.cleanup.cron}")
  public void prunePacketsOfAgedFiles() {
    if (!cleanupProperties.isEnabled() || cleanupProperties.getPacketRetentionHours() <= 0) {
      return;
    }

    LocalDateTime packetExpiry =
        LocalDateTime.now().minusHours(cleanupProperties.getPacketRetentionHours());
    log.info("Pruning packets for files uploaded before: {}", packetExpiry);

    try {
      List<FileEntity> candidates =
          fileRepository.findByPacketsPrunedAtIsNullAndUploadedAtBefore(packetExpiry);
      if (candidates.isEmpty()) {
        log.info("No files with packets due for pruning");
        return;
      }

      int prunedCount = 0;
      int failureCount = 0;

      for (FileEntity file : candidates) {
        try {
          packetPartitions.dropPartition(file.getId());
          // Marked regardless of whether a partition was actually there: either way the file now
          // has no packets, and the timestamp is what stops it being swept again next cycle.
          file.setPacketsPrunedAt(LocalDateTime.now());
          fileRepository.save(file);
          prunedCount++;
        } catch (Exception e) {
          log.error(
              "Failed to prune packets for file: {} (ID: {})", file.getFileName(), file.getId(), e);
          failureCount++;
        }
      }

      log.info("Packet pruning completed. Pruned: {}, Failed: {}", prunedCount, failureCount);

    } catch (Exception e) {
      log.error("Error during scheduled packet pruning", e);
    }
  }
}
