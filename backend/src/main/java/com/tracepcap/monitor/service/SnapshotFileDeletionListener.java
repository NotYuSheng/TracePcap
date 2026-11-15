package com.tracepcap.monitor.service;

import com.tracepcap.file.event.FileDeletedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Keeps monitor networks consistent when a snapshot's file is deleted (#635).
 *
 * <p>A snapshot row is FK-cascaded away with its file. Removing a snapshot from the UI goes through
 * {@link SnapshotService#removeSnapshot}, which then renumbers the remaining snapshots and re-runs
 * change detection. Two other paths delete the file directly and skipped both steps:
 * {@code MONITOR_FILE_RETENTION_HOURS} cleanup, and a delete from the files list. They left gaps in
 * snapshot_order, plus change events whose from_snapshot_id the cascade had set to NULL.
 *
 * <p>By the time the event fires, the snapshot row is already gone, along with which network it
 * belonged to. So instead of tracking the snapshot, this repairs whichever networks now have a gap.
 * That covers every delete path, including ones added later, and costs one grouped query when
 * nothing needs repair. Deleting the newest snapshot leaves no gap, and that case needs no repair
 * either: its change events cascade away with it.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SnapshotFileDeletionListener {

  private final SnapshotService snapshotService;

  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
  public void onFileDeleted(FileDeletedEvent event) {
    try {
      snapshotService.repairNetworksWithSnapshotGaps();
    } catch (Exception e) {
      // The file delete already succeeded and must not be reported as failed. The repair is
      // idempotent and runs again on the next delete, and a UI snapshot removal does the same steps.
      log.error("Failed to repair monitor snapshot order after deleting file {}", event.getFileId(), e);
    }
  }
}
