package com.tracepcap.cleanup;

import com.tracepcap.config.CleanupProperties;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.file.service.FileService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Service to handle scheduled cleanup of expired files
 */
@Slf4j
@Service
@RequiredArgsConstructor
@ConditionalOnProperty(prefix = "tracepcap.cleanup", name = "enabled", havingValue = "true", matchIfMissing = true)
public class FileCleanupService {

    private final FileRepository fileRepository;
    private final FileService fileService;
    private final CleanupProperties cleanupProperties;

    /**
     * Scheduled task to clean up expired files
     * Runs according to the cron expression configured in application.yml
     */
    @Scheduled(cron = "${tracepcap.cleanup.cron}")
    public void cleanupExpiredFiles() {
        if (!cleanupProperties.isEnabled()) {
            log.debug("File cleanup is disabled");
            return;
        }

        log.info("Starting scheduled file cleanup task");

        try {
            // Calculate expiry timestamp (current time - retention hours)
            LocalDateTime expiryTimestamp = LocalDateTime.now()
                    .minusHours(cleanupProperties.getRetentionHours());

            log.info("Looking for files uploaded before: {}", expiryTimestamp);

            // Find all files older than retention period
            List<FileEntity> expiredFiles = fileRepository.findByUploadedAtBefore(expiryTimestamp);

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
                    log.info("Deleting expired file: {} (ID: {}, uploaded at: {})",
                            file.getFileName(), file.getId(), file.getUploadedAt());

                    fileService.deleteFile(file.getId());
                    successCount++;

                } catch (Exception e) {
                    log.error("Failed to delete expired file: {} (ID: {})",
                            file.getFileName(), file.getId(), e);
                    failureCount++;
                }
            }

            log.info("File cleanup completed. Successfully deleted: {}, Failed: {}",
                    successCount, failureCount);

        } catch (Exception e) {
            log.error("Error during scheduled file cleanup", e);
        }
    }
}
