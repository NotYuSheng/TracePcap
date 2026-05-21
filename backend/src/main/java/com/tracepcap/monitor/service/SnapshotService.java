package com.tracepcap.monitor.service;

import com.tracepcap.common.exception.InvalidFileException;
import com.tracepcap.common.exception.ResourceNotFoundException;
import com.tracepcap.file.entity.FileEntity;
import com.tracepcap.file.entity.FileEntity.FileStatus;
import com.tracepcap.file.repository.FileRepository;
import com.tracepcap.insights.repository.SnapshotInsightRepository;
import com.tracepcap.monitor.dto.NetworkSnapshotDto;
import com.tracepcap.monitor.dto.PatchSnapshotRequest;
import com.tracepcap.monitor.entity.NetworkEntity;
import com.tracepcap.monitor.entity.NetworkSnapshotEntity;
import com.tracepcap.monitor.repository.NetworkChangeEventRepository;
import com.tracepcap.monitor.repository.NetworkSnapshotRepository;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class SnapshotService {

  private final NetworkService networkService;
  private final NetworkSnapshotRepository snapshotRepository;
  private final FileRepository fileRepository;
  private final ChangeDetectionService changeDetectionService;
  private final NetworkChangeEventRepository changeEventRepository;
  private final SnapshotInsightRepository snapshotInsightRepository;

  @Transactional(readOnly = true)
  public List<NetworkSnapshotDto> listSnapshots(UUID networkId) {
    networkService.findOrThrow(networkId);
    List<NetworkSnapshotEntity> snapshots =
        snapshotRepository.findByNetworkIdOrderBySnapshotOrderAsc(networkId);
    if (snapshots.isEmpty()) return List.of();

    // Bulk-fetch counts to avoid N+1 queries
    List<UUID> ids = snapshots.stream().map(NetworkSnapshotEntity::getId).collect(Collectors.toList());
    Map<UUID, Long> changeCounts = changeEventRepository.countByToSnapshotIds(ids);
    Map<UUID, Long> criticalCounts = changeEventRepository.countCriticalByToSnapshotIds(ids);

    return snapshots.stream()
        .map(s -> toDto(s, changeCounts.getOrDefault(s.getId(), 0L),
                           criticalCounts.getOrDefault(s.getId(), 0L)))
        .collect(Collectors.toList());
  }

  public NetworkSnapshotDto addSnapshot(UUID networkId, UUID fileId) {
    NetworkEntity network = networkService.findOrThrow(networkId);

    FileEntity file =
        fileRepository
            .findById(fileId)
            .orElseThrow(() -> new ResourceNotFoundException("File not found: " + fileId));

    if (file.getStatus() != FileStatus.COMPLETED) {
      throw new InvalidFileException(
          "File must be COMPLETED before adding to a network. Current status: " + file.getStatus());
    }

    if (snapshotRepository.findByNetworkIdAndFileId(networkId, fileId).isPresent()) {
      throw new InvalidFileException("File is already part of this network.");
    }

    boolean isFirst = snapshotRepository.countByNetworkId(networkId) == 0;

    NetworkSnapshotEntity snapshot =
        NetworkSnapshotEntity.builder()
            .network(network)
            .file(file)
            .snapshotOrder(0)
            .build();
    snapshot = snapshotRepository.save(snapshot);

    // Reorder all snapshots by capture start time
    reorderSnapshots(networkId);

    // Refresh after reorder
    snapshot = snapshotRepository.findById(snapshot.getId()).orElseThrow();

    // Run change detection for the new snapshot and any successor whose predecessor changed
    if (!isFirst) {
      List<NetworkSnapshotEntity> ordered =
          snapshotRepository.findByNetworkIdOrderBySnapshotOrderAsc(networkId);
      int newOrder = snapshot.getSnapshotOrder();
      NetworkSnapshotEntity prev = newOrder > 0 ? ordered.get(newOrder - 1) : null;

      // Detect: prev → new
      if (prev != null) {
        try {
          changeDetectionService.detectChanges(prev, snapshot);
        } catch (Exception e) {
          log.error(
              "Change detection failed for snapshot {} vs {}: {}",
              snapshot.getId(), prev.getId(), e.getMessage(), e);
        }
      }

      // If the new snapshot was inserted mid-timeline, the successor's events now reflect
      // the wrong predecessor. Delete its stale events and re-detect: new → successor.
      if (newOrder + 1 < ordered.size()) {
        NetworkSnapshotEntity successor = ordered.get(newOrder + 1);
        changeEventRepository.deleteByToSnapshotId(successor.getId());
        try {
          changeDetectionService.detectChanges(snapshot, successor);
        } catch (Exception e) {
          log.error(
              "Change detection failed for successor snapshot {} vs {}: {}",
              snapshot.getId(), successor.getId(), e.getMessage(), e);
        }
      }
    }

    long changeCount = changeEventRepository.countByToSnapshotId(snapshot.getId());
    long criticalCount = changeEventRepository.countCriticalByToSnapshotId(snapshot.getId());
    return toDto(snapshot, changeCount, criticalCount);
  }

  public NetworkSnapshotDto patchSnapshot(UUID networkId, UUID snapshotId, PatchSnapshotRequest req) {
    NetworkSnapshotEntity snapshot = snapshotRepository.findById(snapshotId)
        .filter(s -> s.getNetwork().getId().equals(networkId))
        .orElseThrow(() -> new ResourceNotFoundException("Snapshot not found: " + snapshotId));
    if (req.getContext() != null) snapshot.setContext(req.getContext());
    if (req.getNotes() != null) snapshot.setNotes(req.getNotes());
    snapshot = snapshotRepository.save(snapshot);
    long changeCount = changeEventRepository.countByToSnapshotId(snapshotId);
    long criticalCount = changeEventRepository.countCriticalByToSnapshotId(snapshotId);
    return toDto(snapshot, changeCount, criticalCount);
  }

  public void removeSnapshot(UUID networkId, UUID snapshotId) {
    networkService.findOrThrow(networkId);
    snapshotRepository
        .findById(snapshotId)
        .filter(s -> s.getNetwork().getId().equals(networkId))
        .orElseThrow(() -> new ResourceNotFoundException("Snapshot not found: " + snapshotId));

    snapshotRepository.deleteById(snapshotId);
    reorderSnapshots(networkId);
    rerunChangeDetectionChain(networkId);
  }

  // ── Helpers ──────────────────────────────────────────────────────────────────

  /**
   * Recomputes snapshot_order for all snapshots in the network, sorted by file.startTime ASC
   * (ties broken by addedAt ASC).
   */
  private void reorderSnapshots(UUID networkId) {
    List<NetworkSnapshotEntity> ordered =
        snapshotRepository.findOrderedByStartTime(networkId);
    for (int i = 0; i < ordered.size(); i++) {
      NetworkSnapshotEntity s = ordered.get(i);
      if (s.getSnapshotOrder() != i) {
        s.setSnapshotOrder(i);
        snapshotRepository.save(s);
      }
    }
  }

  /**
   * Deletes all change events for the network then re-runs detection for every consecutive pair
   * from the first snapshot onward.
   */
  private void rerunChangeDetectionChain(UUID networkId) {
    changeEventRepository.deleteByNetworkId(networkId);

    List<NetworkSnapshotEntity> ordered =
        snapshotRepository.findByNetworkIdOrderBySnapshotOrderAsc(networkId);
    if (ordered.size() < 2) return;

    for (int i = 1; i < ordered.size(); i++) {
      try {
        changeDetectionService.detectChanges(ordered.get(i - 1), ordered.get(i));
      } catch (Exception e) {
        log.error(
            "Change detection failed between snapshots {} and {}: {}",
            ordered.get(i - 1).getId(), ordered.get(i).getId(), e.getMessage(), e);
      }
    }
  }

  NetworkSnapshotDto toDto(NetworkSnapshotEntity s, long changeCount, long criticalCount) {
    return NetworkSnapshotDto.builder()
        .id(s.getId())
        .networkId(s.getNetwork().getId())
        .fileId(s.getFile().getId())
        .fileName(s.getFile().getFileName())
        .snapshotOrder(s.getSnapshotOrder())
        .startTime(s.getFile().getStartTime())
        .endTime(s.getFile().getEndTime())
        .packetCount(s.getFile().getPacketCount())
        .totalBytes(s.getFile().getTotalBytes())
        .changeCount(changeCount)
        .criticalCount(criticalCount)
        .context(s.getContext())
        .notes(s.getNotes())
        .hasInsights(snapshotInsightRepository.existsBySnapshotId(s.getId()))
        .addedAt(s.getAddedAt())
        .build();
  }
}
