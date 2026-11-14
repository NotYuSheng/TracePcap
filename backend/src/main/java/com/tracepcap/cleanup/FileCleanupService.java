package com.tracepcap.cleanup;

import com.tracepcap.analysis.spi.PacketPartitions;
import com.tracepcap.common.settings.EditablePolicy;
import com.tracepcap.common.settings.RuntimePolicy;
import com.tracepcap.config.CleanupProperties;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.entity.FileEntity.FileSource;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.file.service.FileService;
import java.time.LocalDateTime;
import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
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
  private final NetworkSnapshotRepository snapshotRepository;
  // Retention hours are editable in the app (#915 phase 5), so read them per run, never at startup.
  private final RuntimePolicy runtimePolicy;

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

      // A capture that is a snapshot of a monitored network is kept with the network, whatever it
      // was uploaded as: deleting it would cut a hole in the network's history. It follows the
      // monitor retention instead.
      Set<UUID> inNetworks = filesInNetworks();

      // Analysis files: the analysis retention, unless kept with a network.
      LocalDateTime analysisExpiry =
          LocalDateTime.now().minusHours(runtimePolicy.getInt(EditablePolicy.FILE_RETENTION_HOURS));
      log.info("Checking analysis files uploaded before: {}", analysisExpiry);
      fileRepository.findBySourceAndUploadedAtBefore(FileSource.ANALYSIS, analysisExpiry).stream()
          .filter(f -> !inNetworks.contains(f.getId()))
          .forEach(expiredFiles::add);

      // Monitor files, and analysis files kept with a network: only when monitorRetentionHours > 0.
      int monitorRetentionHours = runtimePolicy.getInt(EditablePolicy.MONITOR_FILE_RETENTION_HOURS);
      if (monitorRetentionHours > 0) {
        LocalDateTime monitorExpiry = LocalDateTime.now().minusHours(monitorRetentionHours);
        log.info("Checking monitor files uploaded before: {}", monitorExpiry);
        expiredFiles.addAll(
            fileRepository.findBySourceAndUploadedAtBefore(FileSource.MONITOR, monitorExpiry));
        fileRepository.findBySourceAndUploadedAtBefore(FileSource.ANALYSIS, monitorExpiry).stream()
            .filter(f -> inNetworks.contains(f.getId()))
            .forEach(expiredFiles::add);
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

  /** Every capture that is a snapshot of at least one monitored network. */
  private Set<UUID> filesInNetworks() {
    Set<UUID> out = new HashSet<>();
    for (Object[] row : snapshotRepository.findAllMemberships()) {
      out.add((UUID) row[1]);
    }
    return out;
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
    int packetRetentionHours = runtimePolicy.getInt(EditablePolicy.PACKET_RETENTION_HOURS);
    if (!cleanupProperties.isEnabled() || packetRetentionHours <= 0) {
      return;
    }

    LocalDateTime packetExpiry = LocalDateTime.now().minusHours(packetRetentionHours);
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
