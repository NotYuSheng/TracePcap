package com.tracepcap.cleanup;

import com.tracepcap.analysis.spi.PacketPartitions;
import com.tracepcap.file.event.FileDeletedEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Drops a deleted file's packet partition (#394).
 *
 * <p>Deleting a file cascades away its packet rows but leaves the partition itself attached to
 * {@code packets}; without this, every deleted file would leak an empty table and the partition
 * count would climb until planning slowed down.
 *
 * <p>Lives in {@code cleanup} rather than {@code file} because dropping the partition means calling
 * into {@code analysis}, and a direct {@code file → analysis} dependency closes a module cycle that
 * {@code LayerDependencyTest} rejects. {@code cleanup} already depends on both.
 *
 * <p>{@code AFTER_COMMIT} so the partition is only dropped once the delete is durable — a rolled
 * back transaction must not take the packets with it.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class PacketPartitionCleanupListener {

  private final PacketPartitions packetPartitions;

  @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT)
  public void handleFileDeleted(FileDeletedEvent event) {
    try {
      packetPartitions.dropPartition(event.getFileId());
    } catch (Exception e) {
      // The file is already gone and the rows with it; a stranded empty partition is wasteful but
      // harmless, and must not surface as a failed delete to the caller.
      log.error("Failed to drop packet partition for deleted file {}", event.getFileId(), e);
    }
  }
}
